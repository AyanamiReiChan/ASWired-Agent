package runtime

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"
)

var errNetworkUnsupported = errors.New("network operation unavailable on this platform or without required privileges")

type WireGuardPeer struct {
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}
type WireGuardSpec struct {
	ID         string          `json:"id"`
	PrivateKey string          `json:"private_key"`
	Addresses  []string        `json:"addresses"`
	ListenPort int             `json:"listen_port,omitempty"`
	MTU        int             `json:"mtu,omitempty"`
	RouteTable int             `json:"route_table,omitempty"`
	Peers      []WireGuardPeer `json:"peers"`
}
type wireGuardState struct {
	Config  WireGuardSpec `json:"config"`
	Enabled bool          `json:"enabled"`
	WARP    bool          `json:"warp"`
}

func wgKey(value string) bool {
	b, e := base64.StdEncoding.DecodeString(value)
	if e != nil || len(b) != 32 {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
func decodeWireGuard(raw map[string]any) (WireGuardSpec, error) {
	b, e := json.Marshal(raw)
	if e != nil {
		return WireGuardSpec{}, e
	}
	var c WireGuardSpec
	if e = json.Unmarshal(b, &c); e != nil {
		return c, e
	}
	if !safeName(c.ID) || !wgKey(c.PrivateKey) {
		return c, errors.New("WireGuard requires a safe id and a supplied 32-byte base64 private key")
	}
	if len(c.Addresses) == 0 || len(c.Addresses) > 8 || len(c.Peers) == 0 || len(c.Peers) > 64 {
		return c, errors.New("WireGuard requires 1..8 addresses and 1..64 peers")
	}
	for _, address := range c.Addresses {
		if _, e = netip.ParsePrefix(address); e != nil {
			return c, errors.New("WireGuard address must be an IPv4/IPv6 CIDR")
		}
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return c, errors.New("invalid WireGuard listen port")
	}
	if c.MTU == 0 {
		c.MTU = 1420
	}
	if c.MTU < 1280 || c.MTU > 9000 {
		return c, errors.New("WireGuard MTU must be 1280..9000")
	}
	if c.RouteTable == 0 {
		c.RouteTable = 51820
	}
	if c.RouteTable < 10000 || c.RouteTable > 2147483647 {
		return c, errors.New("WireGuard requires an explicit isolated route table between 10000 and 2147483647")
	}
	seen := map[string]bool{}
	for _, p := range c.Peers {
		if !wgKey(p.PublicKey) || seen[p.PublicKey] || (p.PresharedKey != "" && !wgKey(p.PresharedKey)) {
			return c, errors.New("invalid or duplicate peer key")
		}
		seen[p.PublicKey] = true
		if e = validNetworkAddress(p.Endpoint, false); e != nil {
			return c, e
		}
		if p.PersistentKeepalive < 0 || p.PersistentKeepalive > 65535 {
			return c, errors.New("invalid persistent keepalive")
		}
		if len(p.AllowedIPs) == 0 || len(p.AllowedIPs) > 256 {
			return c, errors.New("peer allowed_ips must contain 1..256 CIDRs")
		}
		for _, cidr := range p.AllowedIPs {
			if _, e = netip.ParsePrefix(cidr); e != nil {
				return c, errors.New("invalid peer allowed IP CIDR")
			}
		}
	}
	return c, nil
}
func wgInterface(id string) string { return "asw" + digest([]byte(id))[:11] }
func (r *Runtime) wgPaths(id string) (string, string) {
	dir := filepath.Join(r.cfg.DataDir, "wireguard", id)
	return filepath.Join(dir, wgInterface(id)+".conf"), filepath.Join(dir, "state.json")
}
func wgConfig(c WireGuardSpec) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\nMTU = %d\nTable = %d\n", c.PrivateKey, strings.Join(c.Addresses, ", "), c.MTU, c.RouteTable)
	if c.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", c.ListenPort)
	}
	for _, p := range c.Peers {
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = %d\n", p.PublicKey, p.Endpoint, strings.Join(p.AllowedIPs, ", "), p.PersistentKeepalive)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
	}
	return []byte(b.String())
}
func (r *Runtime) networkExec(ctx context.Context, binary string, args ...string) (string, error) {
	if r.hostExec != nil {
		return r.hostExec(ctx, binary, args...)
	}
	if goruntime.GOOS != "linux" {
		return "", errNetworkUnsupported
	}
	return r.run(ctx, binary, args...)
}
func (r *Runtime) wgBinary() string {
	if r.cfg.WireGuardBinary != "" {
		return r.cfg.WireGuardBinary
	}
	return "wg"
}
func (r *Runtime) wgQuickBinary() string {
	if r.cfg.WireGuardQuickBinary != "" {
		return r.cfg.WireGuardQuickBinary
	}
	return "wg-quick"
}
func (r *Runtime) ipBinary() string {
	if r.cfg.IPBinary != "" {
		return r.cfg.IPBinary
	}
	return "ip"
}
func (r *Runtime) wgExists(ctx context.Context, name string) (bool, error) {
	out, e := r.networkExec(ctx, r.wgBinary(), "show", "interfaces")
	if e != nil {
		return false, e
	}
	for _, v := range strings.Fields(out) {
		if v == name {
			return true, nil
		}
	}
	return false, nil
}
func wgExpectedPublic(c WireGuardSpec) string {
	b, _ := base64.StdEncoding.DecodeString(c.PrivateKey)
	key, e := ecdh.X25519().NewPrivateKey(b)
	if e != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}
func (r *Runtime) verifyWireGuard(ctx context.Context, c WireGuardSpec) error {
	out, e := r.networkExec(ctx, r.wgBinary(), "show", wgInterface(c.ID), "public-key")
	if e != nil {
		return errors.New("WireGuard interface verification failed")
	}
	if strings.TrimSpace(out) != wgExpectedPublic(c) {
		return errors.New("WireGuard interface identity differs from the managed configuration")
	}
	return nil
}
func (r *Runtime) applyWireGuard(ctx context.Context, p map[string]any, warp bool) (map[string]any, error) {
	c, e := decodeWireGuard(p)
	if e != nil {
		return nil, e
	}
	path, statePath := r.wgPaths(c.ID)
	oldBytes, e := os.ReadFile(statePath)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	var old wireGuardState
	if len(oldBytes) > 0 {
		if e = json.Unmarshal(oldBytes, &old); e != nil {
			return nil, e
		}
		if old.WARP != warp {
			return nil, errors.New("managed tunnel kind cannot change")
		}
	}
	exists, e := r.wgExists(ctx, wgInterface(c.ID))
	if e != nil {
		return nil, e
	}
	if exists && len(oldBytes) == 0 {
		return nil, errors.New("interface already exists without ASWired ownership")
	}
	if exists {
		if e = r.verifyWireGuard(ctx, old.Config); e != nil {
			return nil, e
		}
	}
	oldConfig, e := os.ReadFile(path)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if exists {
		if _, e = r.networkExec(ctx, r.wgQuickBinary(), "down", path); e != nil {
			return nil, errors.New("could not stop the previous WireGuard interface; original configuration retained")
		}
	}
	rollback := func(cause error) (map[string]any, error) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		clean := true
		if running, err := r.wgExists(cleanupCtx, wgInterface(c.ID)); err != nil {
			clean = false
		} else if running {
			if _, err = r.networkExec(cleanupCtx, r.wgQuickBinary(), "down", path); err != nil {
				clean = false
			}
		}
		if len(oldConfig) > 0 {
			if atomicWrite(path, oldConfig, 0600) != nil {
				clean = false
			}
		} else if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			clean = false
		}
		if exists && clean {
			if _, err := r.networkExec(cleanupCtx, r.wgQuickBinary(), "up", path); err != nil {
				clean = false
			} else if r.verifyWireGuard(cleanupCtx, old.Config) != nil {
				clean = false
			}
		}
		return map[string]any{"applied": false, "rollback_succeeded": clean, "previous_interface_restored": exists && clean}, cause
	}
	if e = atomicWrite(path, wgConfig(c), 0600); e != nil {
		return rollback(e)
	}
	if _, e = r.networkExec(ctx, r.wgQuickBinary(), "up", path); e != nil {
		return rollback(errors.New("WireGuard activation failed; check installed kernel support, privileges, endpoint and route conflicts"))
	}
	if e = r.verifyWireGuard(ctx, c); e != nil {
		return rollback(e)
	}
	state := wireGuardState{Config: c, Enabled: true, WARP: warp}
	saved, _ := json.MarshalIndent(state, "", "  ")
	if e = atomicWrite(statePath, saved, 0600); e != nil {
		return rollback(e)
	}
	return map[string]any{"applied": true, "persisted": true, "id": c.ID, "interface": wgInterface(c.ID), "route_table": c.RouteTable, "addresses": c.Addresses, "warp": warp, "account_registered": false, "tunnel_verified": false, "note": "interface configuration verified; a handshake or explicit traffic probe is required to verify the peer"}, nil
}
func (r *Runtime) wireGuardStatus(ctx context.Context, p map[string]any) (map[string]any, error) {
	id, _ := p["id"].(string)
	if !safeName(id) {
		return nil, errors.New("valid tunnel id required")
	}
	_, statePath := r.wgPaths(id)
	b, e := os.ReadFile(statePath)
	if e != nil {
		return nil, e
	}
	var state wireGuardState
	if e = json.Unmarshal(b, &state); e != nil {
		return nil, e
	}
	name := wgInterface(id)
	exists, e := r.wgExists(ctx, name)
	if e != nil {
		return nil, e
	}
	result := map[string]any{"id": id, "interface": name, "configured": state.Enabled, "running": exists, "warp": state.WARP, "addresses": state.Config.Addresses, "route_table": state.Config.RouteTable, "timestamp": time.Now().Unix(), "account_registration": "user-supplied"}
	if !exists {
		return result, nil
	}
	if e = r.verifyWireGuard(ctx, state.Config); e != nil {
		return nil, e
	}

	fields := map[string]string{"endpoints": "endpoints", "latest_handshakes": "latest-handshakes", "transfer": "transfer", "allowed_ips": "allowed-ips"}
	peerValues := map[string]map[string]any{}
	for outputName, field := range fields {
		out, e := r.networkExec(ctx, r.wgBinary(), "show", name, field)
		if e != nil {
			return nil, fmt.Errorf("WireGuard %s query failed", field)
		}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			columns := strings.Fields(line)
			if len(columns) < 2 {
				continue
			}
			peer := peerValues[columns[0]]
			if peer == nil {
				peer = map[string]any{"public_key": columns[0]}
				peerValues[columns[0]] = peer
			}
			switch field {
			case "latest-handshakes":
				n, e := strconv.ParseInt(columns[1], 10, 64)
				if e == nil {
					peer[outputName] = n
					peer["has_handshake"] = n > 0
				}
			case "transfer":
				if len(columns) >= 3 {
					rx, _ := strconv.ParseUint(columns[1], 10, 64)
					tx, _ := strconv.ParseUint(columns[2], 10, 64)
					peer["received_bytes"] = rx
					peer["sent_bytes"] = tx
				}
			default:
				peer[outputName] = strings.Join(columns[1:], " ")
			}
		}
	}
	result["peers"] = peerValues
	link, e := r.networkExec(ctx, r.ipBinary(), "-json", "link", "show", "dev", name)
	if e != nil {
		return nil, errors.New("WireGuard link status query failed")
	}
	var linkData any
	if e = json.Unmarshal([]byte(link), &linkData); e != nil {
		return nil, errors.New("invalid ip link JSON response")
	}
	result["link"] = linkData
	return result, nil
}
func (r *Runtime) removeWireGuard(ctx context.Context, p map[string]any) (map[string]any, error) {
	id, _ := p["id"].(string)
	if !safeName(id) {
		return nil, errors.New("valid tunnel id required")
	}
	path, statePath := r.wgPaths(id)
	b, e := os.ReadFile(statePath)
	if e != nil {
		return nil, e
	}
	var state wireGuardState
	if e = json.Unmarshal(b, &state); e != nil {
		return nil, e
	}
	running, e := r.wgExists(ctx, wgInterface(id))
	if e != nil {
		return nil, e
	}
	if running {
		if e = r.verifyWireGuard(ctx, state.Config); e != nil {
			return nil, e
		}
		if _, e = r.networkExec(ctx, r.wgQuickBinary(), "down", path); e != nil {
			return nil, errors.New("WireGuard removal failed; saved configuration retained")
		}
	}
	state.Enabled = false
	b, _ = json.Marshal(state)
	if e = atomicWrite(statePath, b, 0600); e != nil {
		return nil, e
	}
	if e = os.Remove(path); e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if e = os.Remove(statePath); e != nil {
		return nil, e
	}
	return map[string]any{"removed": true, "id": id, "account_unregistered": false}, nil
}
func (r *Runtime) restoreWireGuard(ctx context.Context) error {
	entries, e := os.ReadDir(filepath.Join(r.cfg.DataDir, "wireguard"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if !entry.IsDir() || !safeName(entry.Name()) {
			continue
		}
		path, statePath := r.wgPaths(entry.Name())
		b, e := os.ReadFile(statePath)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		var state wireGuardState
		if e = json.Unmarshal(b, &state); e != nil {
			return e
		}
		if !state.Enabled {
			continue
		}
		encoded, _ := json.Marshal(state.Config)
		var raw map[string]any
		json.Unmarshal(encoded, &raw)
		if _, e = decodeWireGuard(raw); e != nil {
			return e
		}
		exists, e := r.wgExists(ctx, wgInterface(state.Config.ID))
		if e != nil {
			return e
		}
		if !exists {
			if e = atomicWrite(path, wgConfig(state.Config), 0600); e != nil {
				return e
			}
			if _, e = r.networkExec(ctx, r.wgQuickBinary(), "up", path); e != nil {
				return errors.New("persisted WireGuard interface could not start")
			}
		}
		if e = r.verifyWireGuard(ctx, state.Config); e != nil {
			return e
		}
	}
	return nil
}
