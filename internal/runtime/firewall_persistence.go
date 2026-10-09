package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
)

type firewallDirectorySyncError struct{ error }

// The files themselves are synced by atomicWrite. Linux also requires a directory
// sync to make the journal/commit rename or removal durable across power loss.
func (r *Runtime) syncFirewallDirectory() error {
	if r.firewallSyncDir != nil {
		return r.firewallSyncDir(r.cfg.DataDir)
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	dir, err := os.Open(r.cfg.DataDir)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func (r *Runtime) removeFirewallJournal() error {
	path := r.firewallPath("firewall-pending.json")
	journal, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	if err = r.syncFirewallDirectory(); err != nil {
		// The unlink may not be durable. Restore the recovery intent in this
		// process as well, so a failed cleanup cannot be mistaken for success.
		restoreErr := atomicWrite(path, journal, 0600)
		if restoreErr == nil {
			restoreErr = r.syncFirewallDirectory()
		}
		return errors.Join(err, restoreErr)
	}
	return nil
}

func (r *Runtime) firewallPersistenceFailure(ctx context.Context, cause error) (map[string]any, error) {
	r.firewallReady = false
	if err := r.stop(ctx); err != nil {
		cause = errors.Join(cause, fmt.Errorf("stop proxy listeners: %w", err))
	}
	data, _ := r.firewallStatus(ctx)
	data["applied"] = false
	data["lastError"] = "firewall persistence failed; listener startup remains blocked: " + cause.Error()
	r.firewallStatusCache = data
	return data, errors.New(data["lastError"].(string))
}

func managementPort(listen string) int {
	_, value, _ := net.SplitHostPort(listen)
	port, _ := strconv.Atoi(value)
	if port == 0 {
		return 23889
	}
	return port
}

// UpdateConnection is an optional control.Runner extension. The caller holds its
// own configuration lock; Runtime never calls back into that lock. Keeping our
// lock through persistence prevents a simultaneous firewall apply from selecting
// a new management port between validation and publication.
func (r *Runtime) UpdateConnection(mode, listen string, persist func() error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, value, err := net.SplitHostPort(listen)
	port, parseErr := strconv.Atoi(value)
	if err != nil || parseErr != nil || port < 1 || port > 65535 {
		return errors.New("management listen address requires a port from 1..65535")
	}
	// Inspect both files: pending removal does not yet prove that the previously
	// protected port has been released in the kernel.
	for _, file := range []string{"firewall.json", "firewall-pending.json"} {
		state, readErr := r.readFirewallFile(file)
		if readErr != nil {
			return fmt.Errorf("cannot validate management port against firewall state: %w", readErr)
		}
		if state != nil {
			for _, rule := range state.Rules {
				if rule.Port == port {
					return errors.New("remove the firewall allowlist before using its protected port for Agent management")
				}
			}
		}
	}
	if err = persist(); err != nil {
		return err
	}
	if r.managementPorts == nil {
		r.managementPorts = map[int]bool{}
	}
	// Old HTTP listeners close asynchronously after the control client receives
	// its change notification. Keep every management port reserved until restart.
	r.managementPorts[managementPort(r.cfg.ListenAddress)] = true
	r.managementPorts[port] = true
	r.cfg.ConnectionMode, r.cfg.ListenAddress = mode, listen
	return nil
}
