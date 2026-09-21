package control

import (
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"strings"
	"time"
)

func (c *Client) rotateIdentity(command wire.Command) wire.Result {
	fail := func(message string) wire.Result { return wire.Result{ID: command.ID, Status: "failed", Error: message} }
	token, _ := command.Params["token"].(string)
	agentToken, _ := command.Params["agent_token"].(string)
	for _, value := range []string{token, agentToken} {
		if len(value) < 32 || len(value) > 4096 || strings.ContainsAny(value, " \t\r\n") {
			return fail("new identity tokens must be nonempty, at least 32 characters and free of whitespace")
		}
	}
	if c.cfg.ConfigPath == "" {
		return fail("cannot rotate identity without the current local configuration file")
	}
	if token == c.cfg.Token && agentToken == c.cfg.AgentToken {
		return wire.Result{ID: command.ID, Status: "success", Data: map[string]any{"persisted": true, "previous_expires_at": c.cfg.PreviousTokenExpires}}
	}
	expires := time.Now().Add(15 * time.Minute).Unix()
	if raw, present := command.Params["previous_expires_at"]; present {
		switch v := raw.(type) {
		case float64:
			if v != float64(int64(v)) {
				return fail("invalid previous token expiry")
			}
			expires = int64(v)
		case int64:
			expires = v
		case int:
			expires = int64(v)
		case json.Number:
			var e error
			expires, e = v.Int64()
			if e != nil {
				return fail("invalid previous token expiry")
			}
		default:
			return fail("invalid previous token expiry")
		}
	}
	if expires < 0 || expires > time.Now().Add(15*time.Minute).Unix() {
		return fail("previous token grace period cannot exceed 15 minutes")
	}
	if e := config.RotateCredentials(c.cfg.ConfigPath, token, agentToken, c.cfg.AgentToken, expires); e != nil {
		return fail("could not persist new identity; current identity retained")
	}
	c.cfg.PreviousAgentToken = c.cfg.AgentToken
	c.cfg.PreviousTokenExpires = expires
	c.cfg.Token = token
	c.cfg.AgentToken = agentToken
	return wire.Result{ID: command.ID, Status: "success", Data: map[string]any{"persisted": true, "previous_expires_at": expires}}
}
