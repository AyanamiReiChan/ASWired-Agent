package control

import (
	"errors"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"net"
)

func (c *Client) connectionSettings() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.ConnectionMode, c.cfg.ListenAddress
}

// Called with c.mu held, so connection and identity writes cannot race.
func (c *Client) setConnectionLocked(mode, listen string) error {
	if mode == "" {
		return nil
	}
	if !config.ValidConnectionMode(mode) {
		return errors.New("controller returned invalid connection mode")
	}
	if listen == "" {
		listen = c.cfg.ListenAddress
	}
	if _, _, err := net.SplitHostPort(listen); err != nil {
		return errors.New("controller returned invalid listen address")
	}
	if mode == c.cfg.ConnectionMode && listen == c.cfg.ListenAddress {
		return nil
	}
	if (mode == "auto" || mode == "http") && c.cfg.AgentToken == "" {
		return errors.New("agent_token is required for HTTP management")
	}
	if c.cfg.ConfigPath == "" {
		return errors.New("cannot persist connection settings without a configuration file; upgrade or reinstall Agent")
	}
	persist := func() error {
		if err := config.SaveConnection(c.cfg.ConfigPath, mode, listen); err != nil {
			return errors.New("could not persist connection settings; current connection retained")
		}
		return nil
	}
	// Runtime serializes validation and persistence with firewall application.
	// Lock order is Client.mu then Runtime.mu; the callback never acquires Client.mu.
	if validator, ok := c.run.(interface {
		UpdateConnection(string, string, func() error) error
	}); ok {
		if err := validator.UpdateConnection(mode, listen, persist); err != nil {
			return err
		}
	} else if err := persist(); err != nil {
		return err
	}
	c.cfg.ConnectionMode, c.cfg.ListenAddress = mode, listen
	select {
	case c.changed <- struct{}{}:
	default:
	}
	return nil
}
