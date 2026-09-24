package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func parseConfig(b []byte) (*core.Config, error) {
	if len(b) > 8<<20 {
		return nil, errors.New("config exceeds 8 MiB")
	}
	return serial.LoadJSONConfig(bytes.NewReader(b))
}

func (r *Runtime) applyConfig(ctx context.Context, b []byte) (map[string]any, error) {
	old, readErr := os.ReadFile(r.cfg.XrayConfig)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, readErr
	}
	b, err := r.preserveFederationConfig(b, old)
	if err != nil {
		return nil, err
	}
	if err = ensureGeoAssets(ctx, b); err != nil {
		return nil, err
	}
	parsed, err := parseConfig(b)
	if err != nil {
		return nil, fmt.Errorf("configuration validation: %w", err)
	}
	r.managedCoreLogs(parsed)
	if len(old) > 0 {
		sum := sha256.Sum256(old)
		p := filepath.Join(r.cfg.DataDir, "history", fmt.Sprintf("%d-%s.json", time.Now().UnixNano(), hex.EncodeToString(sum[:8])))
		if err = atomicWrite(p, old, 0600); err != nil {
			return nil, err
		}
	}
	if err = atomicWrite(r.cfg.XrayConfig, b, 0600); err != nil {
		return nil, err
	}
	{
		if r.instance != nil {
			if err = r.instance.Close(); err != nil {
				r.instance = nil
				return nil, fmt.Errorf("saved but previous core could not close: %w", err)
			}
			r.instance = nil
		}
		var instance *core.Instance
		err = r.advanceGeneration()
		if err == nil {
			instance, err = core.New(parsed)
		}
		if err == nil {
			err = configureProxyNetwork(instance, b)
		}
		if err == nil {
			err = instance.Start()
		}
		if err == nil {
			r.instance = instance
			r.startedAt = time.Now()
			r.lastError = ""
		} else {
			if instance != nil {
				_ = instance.Close()
			}
		}
	}
	if err != nil {
		applyErr := err
		r.lastError = applyErr.Error()
		rollback := "no previous configuration"
		if len(old) > 0 {
			if e := atomicWrite(r.cfg.XrayConfig, old, 0600); e != nil {
				rollback = e.Error()
			} else if e = r.recoverCore(ctx); e != nil {
				rollback = e.Error()
			} else {
				rollback = "previous configuration restored and started"
			}
		} else {
			if e := os.Remove(r.cfg.XrayConfig); e != nil && !os.IsNotExist(e) {
				rollback = e.Error()
			}
		}
		actual, _ := os.ReadFile(r.cfg.XrayConfig)
		return map[string]any{"saved": len(actual) > 0 && digest(actual) == digest(b), "applied": false, "recovery": rollback}, fmt.Errorf("core apply failed: %w; recovery: %s", applyErr, rollback)
	}
	return map[string]any{"saved": true, "applied": true, "sha256": digest(b), "mode": r.cfg.XrayMode, "generation": r.generation}, nil
}

func (r *Runtime) recoverCore(ctx context.Context) error {
	return r.start(ctx)
}

func (r *Runtime) start(ctx context.Context) error {
	if r.instance != nil {
		return nil
	}
	b, err := os.ReadFile(r.cfg.XrayConfig)
	if err != nil {
		return err
	}
	if err = ensureGeoAssets(ctx, b); err != nil {
		return err
	}
	c, err := parseConfig(b)
	if err != nil {
		return err
	}
	r.managedCoreLogs(c)
	if err = r.advanceGeneration(); err != nil {
		return err
	}
	x, err := core.New(c)
	if err != nil {
		return err
	}
	if err = configureProxyNetwork(x, b); err != nil {
		_ = x.Close()
		return err
	}
	if err = x.Start(); err != nil {
		_ = x.Close()
		return err
	}
	r.instance = x
	r.startedAt = time.Now()
	return nil
}
func (r *Runtime) stop(ctx context.Context) error {
	if r.instance == nil {
		return nil
	}
	err := r.instance.Close()
	r.instance = nil
	return err
}
func (r *Runtime) status(ctx context.Context) map[string]any {
	s := map[string]any{"mode": r.cfg.XrayMode, "core_version": core.Version(), "generation": r.generation, "agent_pid": os.Getpid(), "running": r.instance != nil, "config_exists": false}
	if b, e := os.ReadFile(r.cfg.XrayConfig); e == nil {
		s["config_exists"] = true
		s["config_sha256"] = digest(b)
		var cfg struct {
			Inbounds []struct {
				Tag string `json:"tag"`
			} `json:"inbounds"`
		}
		if json.Unmarshal(b, &cfg) == nil {
			tags := []string{}
			for _, inbound := range cfg.Inbounds {
				tags = append(tags, inbound.Tag)
			}
			s["inbound_tags"] = tags
		}
	}
	if r.instance != nil {
		s["pid"] = os.Getpid()
		s["started_at"] = r.startedAt.Unix()
	}
	if r.lastError != "" {
		s["last_error"] = r.lastError
	}
	return s
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func (r *Runtime) run(ctx context.Context, binary string, args ...string) (string, error) {
	if r.hostExec != nil {
		return r.hostExec(ctx, binary, args...)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	var out limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s failed: %w: %s", filepath.Base(binary), err, out.String())
	}
	return out.String(), nil
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 64<<10 {
		max := 64<<10 - b.Len()
		if len(p) > max {
			p = p[:max]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

func configBytes(v any) ([]byte, error) {
	if s, ok := v.(string); ok {
		return []byte(s), nil
	}
	if v == nil {
		return nil, errors.New("config is required")
	}
	return json.MarshalIndent(v, "", "  ")
}
