package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/auxiliary"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/logfiles"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/realityscan"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"github.com/xtls/xray-core/common/aswired"
	"github.com/xtls/xray-core/core"
)

type Runtime struct {
	logs       map[string]*logfiles.Manager
	mu         sync.Mutex
	cfg        config.Config
	instance   *core.Instance
	startedAt  time.Time
	generation uint64
	lastError  string
	policies   *policies
	forwards   *forwardManager
	hostExec   func(context.Context, string, ...string) (string, error)
	mihomo     *auxiliary.Manager
}

func New(c config.Config) (*Runtime, error) {
	if c.XrayMode != "embedded" {
		return nil, errors.New("only embedded Xray is supported")
	}
	configuredRoot, err := filepath.Abs(c.DataDir)
	if err != nil {
		return nil, err
	}
	c.DataDir, err = canonicalManagedRoot(c.DataDir)
	if err != nil {
		return nil, err
	}
	c.XrayConfig, err = rebaseManagedPath(c.XrayConfig, configuredRoot, c.DataDir)
	if err != nil {
		return nil, err
	}
	c.NginxConfig, err = rebaseManagedPath(c.NginxConfig, configuredRoot, c.DataDir)
	if err != nil {
		return nil, err
	}
	r := &Runtime{cfg: c, policies: newPolicies(), forwards: newForwardManager()}
	var auxiliaryError error
	r.mihomo, auxiliaryError = auxiliary.New(auxiliary.Config{Binary: c.MihomoBinary, Version: c.MihomoVersion, SHA256: c.MihomoSHA256, DataDir: c.DataDir, ValidateUser: func(email string) error {
		r.policies.mu.Lock()
		defer r.policies.mu.Unlock()
		if r.policies.state(email).value.IPLimit > 0 {
			return errors.New("auxiliary protocols cannot preserve the original client IP; remove the IP limit or use a native protocol")
		}
		return nil
	}})
	if auxiliaryError != nil {
		return nil, auxiliaryError
	}
	if e := r.validateLegacyMode(); e != nil {
		return nil, e
	}
	if b, e := os.ReadFile(filepath.Join(c.DataDir, "core-generation")); e == nil {
		r.generation, e = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if e != nil {
			return nil, errors.New("invalid persisted core generation")
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if e := r.loadPolicies(); e != nil {
		return nil, e
	}
	if r.cfg.XrayMode == "embedded" {
		aswired.Install(r.policies)
	}
	if e := r.initLogs(); e != nil {
		return nil, e
	}
	return r, nil
}
func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var failures []error
	if e := r.restoreForwards(); e != nil {
		failures = append(failures, fmt.Errorf("restore forwards: %w", e))
	}
	if e := r.restoreWireGuard(ctx); e != nil {
		failures = append(failures, fmt.Errorf("restore WireGuard: %w", e))
	}
	if _, e := os.Stat(r.cfg.XrayConfig); os.IsNotExist(e) {
		return errors.Join(failures...)
	}
	if e := r.start(ctx); e != nil {
		failures = append(failures, e)
		return errors.Join(failures...)
	}
	if e := r.mihomo.Start(ctx); e != nil {
		failures = append(failures, fmt.Errorf("restore mihomo: %w", e))
	}
	return errors.Join(failures...)
}
func (r *Runtime) Close() error {
	defer r.closeLogs()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forwards.close()
	r.mihomo.Close()
	if r.instance != nil {
		err := r.instance.Close()
		r.instance = nil
		return err
	}
	return nil
}
func (r *Runtime) Snapshot() map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out := map[string]any{}
	r.mu.Lock()
	defer r.mu.Unlock()
	out["core"] = r.status(ctx)
	out["vision_splice"] = r.policies.spliceObservation()
	out["network_forward"] = r.forwards.status()
	out["mihomo"] = r.mihomo.Snapshot()
	if stats, e := r.readStats(ctx); e == nil {
		out["xray_stats"] = stats
	}
	return out
}
func (r *Runtime) Capabilities() map[string]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]bool{"managed_account_reload": true, "managed_protocols_v2": true, "reality_scan": true, "embedded_core": true, "core_config": true, "dynamic_users": true, "xray_stats": true, "tcp_udp_forward": true, "network_quality_tcp": true, "network_quality_icmp": true, "wireguard": goruntime.GOOS == "linux", "warp_supplied_config": goruntime.GOOS == "linux", "certificate_deploy": true, "ports_check": true, "network_tcp_latency": true, "nginx_control": goruntime.GOOS == "linux", "service_control": goruntime.GOOS == "linux", "vision_splice_hook": r.cfg.XrayMode == "embedded" && (goruntime.GOOS == "linux" || goruntime.GOOS == "android"), "vision_splice_verified": false, "shared_rate_limit": r.cfg.XrayMode == "embedded", "connection_limits": r.cfg.XrayMode == "embedded", "simultaneous_ip_limits": r.cfg.XrayMode == "embedded", "federation": true, "mihomo_auxiliary": r.mihomo.Available(), "mihomo_original_ip": false, "snell": r.mihomo.Available(), "anytls": r.mihomo.Available()}
}
func timeNowMillis() int64 { return time.Now().UnixMilli() }

func (r *Runtime) advanceGeneration() error {
	if r.generation >= 9007199254740990 {
		return errors.New("core generation exhausted")
	}
	next := r.generation + 1
	if e := atomicWrite(filepath.Join(r.cfg.DataDir, "core-generation"), []byte(strconv.FormatUint(next, 10)), 0600); e != nil {
		return e
	}
	r.generation = next
	return nil
}

func (r *Runtime) Handle(ctx context.Context, c wire.Command) wire.Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := wire.Result{ID: c.ID, Status: "success"}
	var data map[string]any
	var err error
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	switch c.Action {
	case "logs.read", "logs.remove":
		data, err = r.logCommand(c)
	case "reality.scan":
		var deadline time.Time
		expires, _ := c.Params["expiresAt"].(string)
		targets, _ := c.Params["targets"].(string)
		deadline, err = time.Parse(time.RFC3339Nano, expires)
		if err == nil && !time.Now().Before(deadline) {
			err = errors.New("REALITY scan request expired")
		}
		if err == nil {
			scanCtx, stop := context.WithDeadline(ctx, deadline)
			data, err = realityscan.Scan(scanCtx, targets)
			stop()
		}
	case "mihomo.config.apply":
		data, err = r.mihomo.Apply(ctx, c.Params["listeners"])
	case "mihomo.users.sync":
		name, _ := c.Params["inbound"].(string)
		data, err = r.mihomo.Sync(ctx, name, c.Params["users"])
	case "mihomo.status":
		data = r.mihomo.Snapshot()
	case "mihomo.config.get":
		data = r.mihomo.Configuration()
	case "mihomo.start", "mihomo.restart":
		data, err = r.mihomo.Activate(ctx)
	case "mihomo.stop":
		data, err = r.mihomo.Stop()
	case "core.status":
		data = r.status(ctx)
	case "core.config.get":
		var b []byte
		b, err = os.ReadFile(r.cfg.XrayConfig)
		if err == nil {
			var cfg any
			err = json.Unmarshal(b, &cfg)
			data = map[string]any{"config": cfg, "sha256": digest(b)}
		}
	case "core.config.test":
		var b []byte
		b, err = configBytes(c.Params["config"])
		if err == nil {
			err = ensureGeoAssets(ctx, b)
		}
		if err == nil {
			_, err = parseConfig(b)
		}
		data = map[string]any{"valid": err == nil}
	case "core.config.apply":
		var b []byte
		b, err = configBytes(c.Params["config"])
		if err == nil {
			data, err = r.applyManagedConfig(ctx, b, c.Params)
		}
	case "core.config.history":
		data, err = r.history()
	case "core.config.restore":
		name, _ := c.Params["name"].(string)
		if !safeName(name) {
			err = errors.New("invalid history filename")
			break
		}
		var b []byte
		b, err = os.ReadFile(filepath.Join(r.cfg.DataDir, "history", name))
		if err == nil {
			data, err = r.applyConfig(ctx, b)
		}
	case "core.start":
		err = r.start(ctx)
		data = r.status(ctx)
	case "core.stop":
		err = r.stop(ctx)
		data = r.status(ctx)
	case "core.restart":
		err = r.stop(ctx)
		if err == nil {
			err = r.start(ctx)
		}
		data = r.status(ctx)
	case "core.users.sync":
		tag, _ := c.Params["inbound"].(string)
		data, err = r.syncOwnerUsers(ctx, tag, c.Params["users"])
	case "core.stats":
		data, err = r.readStats(ctx)
	case "core.policy.apply":
		data, err = r.applyPolicies(c.Params["policies"])
	case "core.connections":
		data = r.policies.snapshot()
	case "federation.identity":
		var public string
		_, public, err = r.federationIdentity()
		data = map[string]any{"public_key": public, "server_id": r.cfg.ServerID, "protocol": wire.FederationProtocol}
	case "federation.grant":
		data, err = r.installFederationGrant(c.Params["signed_grant"])
	case "federation.execute":
		data, err = r.executeFederation(ctx, c.Params["envelope"])
	case "server.ports.check":
		data, err = checkPorts(ctx, c.Params)
	case "server.scan":
		data, err = r.scan(ctx)
	case "certificate.deploy":
		data, err = r.deployCertificate(c.Params)
	case "site.apply":
		data, err = r.applySite(ctx, c.Params)
	case "site.status":
		var output string
		output, err = r.run(ctx, r.cfg.NginxBinary, "-t")
		data = map[string]any{"output": output, "configuration_valid": err == nil}
	case "network.latency":
		data, err = latency(ctx, c.Params)
	case "network.forward.apply":
		data, err = r.applyForwards(c.Params["rules"])
	case "network.forward.status":
		data = r.forwards.status()
	case "network.wireguard.apply", "network.warp.apply":
		data, err = r.applyWireGuard(ctx, c.Params, strings.Contains(c.Action, ".warp."))
	case "network.wireguard.remove", "network.warp.remove":
		data, err = r.removeWireGuard(ctx, c.Params)
	case "network.wireguard.status", "network.warp.status":
		data, err = r.wireGuardStatus(ctx, c.Params)
	case "network.quality":
		data, err = networkQuality(ctx, c.Params)
	default:
		result.Status = "unsupported"
		err = errors.New("unsupported operation: " + c.Action)
	}
	result.Data = data
	if err != nil {
		if errors.Is(err, errNetworkUnsupported) {
			result.Status = "unsupported"
		} else if result.Status != "unsupported" {
			result.Status = "failed"
		}
		result.Error = err.Error()
	}
	return result
}
func (r *Runtime) history() (map[string]any, error) {
	entries, e := os.ReadDir(filepath.Join(r.cfg.DataDir, "history"))
	if os.IsNotExist(e) {
		return map[string]any{"items": []any{}}, nil
	}
	if e != nil {
		return nil, e
	}
	items := []map[string]any{}
	for _, entry := range entries {
		if entry.IsDir() || !safeName(entry.Name()) {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			return nil, e
		}
		items = append(items, map[string]any{"name": entry.Name(), "size": info.Size(), "created_at": info.ModTime().Unix()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["name"].(string) > items[j]["name"].(string) })
	return map[string]any{"items": items}, nil
}
