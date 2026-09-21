package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	commands "github.com/xtls/xray-core/app/proxyman/command"
	statscommand "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	hysteriaaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/protobuf/proto"
)

func makeUser(kind string, raw map[string]any) (*protocol.User, error) {
	email, _ := raw["email"].(string)
	if email == "" {
		return nil, errors.New("every managed user requires a nonempty email")
	}
	u := &protocol.User{Email: email}
	if level, ok := raw["level"].(float64); ok && level >= 0 && level <= 4294967295 {
		u.Level = uint32(level)
	}
	switch kind {
	case "vless", "vmess":
		id, _ := raw["id"].(string)
		if _, e := uuid.ParseString(id); e != nil {
			return nil, fmt.Errorf("invalid UUID for %s", email)
		}
		if kind == "vless" {
			flow, _ := raw["flow"].(string)
			u.Account = serial.ToTypedMessage(&vless.Account{Id: id, Flow: flow})
		} else {
			u.Account = serial.ToTypedMessage(&vmess.Account{Id: id})
		}
	case "trojan":
		password, _ := raw["password"].(string)
		if password == "" {
			return nil, fmt.Errorf("missing password for %s", email)
		}
		u.Account = serial.ToTypedMessage(&trojan.Account{Password: password})
	case "hysteria":
		auth, _ := raw["auth"].(string)
		if auth == "" {
			return nil, fmt.Errorf("missing Hysteria2 auth for %s", email)
		}
		u.Account = serial.ToTypedMessage(&hysteriaaccount.Account{Auth: auth})
	case "shadowsocks":
		password, _ := raw["password"].(string)
		method, _ := raw["method"].(string)
		cipher := shadowsocks.CipherType_UNKNOWN
		switch strings.ToLower(method) {
		case "aes-128-gcm", "aead_aes_128_gcm":
			cipher = shadowsocks.CipherType_AES_128_GCM
		case "aes-256-gcm", "aead_aes_256_gcm":
			cipher = shadowsocks.CipherType_AES_256_GCM
		case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
			cipher = shadowsocks.CipherType_CHACHA20_POLY1305
		case "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305":
			cipher = shadowsocks.CipherType_XCHACHA20_POLY1305
		}
		if password == "" || cipher == shadowsocks.CipherType_UNKNOWN {
			return nil, errors.New("managed Shadowsocks users require a password and a supported traditional AEAD method; SS2022 is not supported by this dynamic-user adapter")
		}
		u.Account = serial.ToTypedMessage(&shadowsocks.Account{Password: password, CipherType: cipher})
	default:
		return nil, fmt.Errorf("dynamic user synchronization is unavailable for protocol %q", kind)
	}
	return u, nil
}

func (r *Runtime) syncUsers(ctx context.Context, tag string, raw any) (map[string]any, error) {
	if tag == "" {
		return nil, errors.New("inbound tag is required")
	}
	old, err := os.ReadFile(r.cfg.XrayConfig)
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err = json.Unmarshal(old, &cfg); err != nil {
		return nil, err
	}
	inbounds, _ := cfg["inbounds"].([]any)
	var entry map[string]any
	for _, v := range inbounds {
		m, _ := v.(map[string]any)
		if m["tag"] == tag {
			entry = m
			break
		}
	}
	if entry == nil {
		return nil, errors.New("inbound is not in the managed configuration")
	}
	users, ok := raw.([]any)
	if !ok {
		return nil, errors.New("users must be an array (use [] to remove all users)")
	}
	kind, _ := entry["protocol"].(string)
	if kind == "socks" || kind == "http" {
		accounts := []any{}
		seen := map[string]bool{}
		for _, value := range users {
			user, ok := value.(map[string]any)
			email, _ := user["email"].(string)
			password, _ := user["password"].(string)
			if !ok || email == "" || password == "" || seen[email] {
				return nil, errors.New("managed accounts require unique emails and passwords")
			}
			if kind == "socks" && (len(email) > 255 || len(password) > 255) {
				return nil, errors.New("SOCKS credentials exceed 255 bytes")
			}
			seen[email] = true
			accounts = append(accounts, map[string]any{"user": email, "pass": password})
		}
		// Empty HTTP accounts disable authentication, so use an unreachable account.
		if len(accounts) == 0 {
			first, second := uuid.New(), uuid.New()
			accounts = append(accounts, map[string]any{"user": "aswired-disabled", "pass": first.String() + second.String()})
		}
		settings, _ := entry["settings"].(map[string]any)
		if settings == nil {
			settings = map[string]any{}
			entry["settings"] = settings
		}
		settings["accounts"] = accounts
		delete(settings, "clients")
		if kind == "socks" {
			settings["auth"] = "password"
		}
		updated, err := json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		result, err := r.applyConfig(ctx, updated)
		if result != nil {
			result["total"] = len(users)
			result["reload_mode"] = "core_restart"
			result["existing_connections"] = "reconnect required"
		}
		return result, err
	}
	settings, _ := entry["settings"].(map[string]any)
	if kind == "shadowsocks" && strings.HasPrefix(fmt.Sprint(settings["method"]), "2022-") {
		return nil, errors.New("SS2022 dynamic user synchronization is unavailable; traditional AEAD and SS2022 credentials must not be mixed")
	}
	desired := map[string]*protocol.User{}
	for _, v := range users {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("invalid user record")
		}
		u, e := makeUser(kind, m)
		if e != nil {
			return nil, e
		}
		if _, exists := desired[u.Email]; exists {
			return nil, errors.New("duplicate user email")
		}
		desired[u.Email] = u
	}
	if settings == nil {
		settings = map[string]any{}
		entry["settings"] = settings
	}
	settings["clients"] = users
	updated, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, err = parseConfig(updated); err != nil {
		return nil, fmt.Errorf("desired users produce invalid core config: %w", err)
	}
	var current []*protocol.User
	var apply func(commands.InboundOperation) error
	{
		if r.instance == nil {
			return nil, errors.New("core is not running")
		}
		manager, ok := r.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
		if !ok {
			return nil, errors.New("inbound manager unavailable")
		}
		handler, e := manager.GetHandler(ctx, tag)
		if e != nil {
			return nil, e
		}
		getter, ok := handler.(proxy.GetInbound)
		if !ok {
			return nil, errors.New("inbound does not expose user manager")
		}
		um, ok := getter.GetInbound().(proxy.UserManager)
		if !ok {
			return nil, errors.New("protocol does not support dynamic users")
		}
		for _, u := range um.GetUsers(ctx) {
			current = append(current, protocol.ToProtoUser(u))
		}
		apply = func(op commands.InboundOperation) error { return op.ApplyInbound(ctx, handler) }
	}
	var added, removed int
	fail := func(e error) (map[string]any, error) {
		{
			_ = r.stop(ctx)
		}
		recovery := r.recoverCore(ctx)
		return map[string]any{"applied": false, "added_before_error": added, "removed_before_error": removed, "recovery_error": fmt.Sprint(recovery)}, fmt.Errorf("user synchronization failed: %w", e)
	}
	for _, u := range current {
		d, exists := desired[u.Email]
		if exists && proto.Equal(u, d) {
			delete(desired, u.Email)
			continue
		}
		if err = apply(&commands.RemoveUserOperation{Email: u.Email}); err != nil {
			return fail(err)
		}
		removed++
	}
	for _, u := range desired {
		if err = apply(&commands.AddUserOperation{User: u}); err != nil {
			return fail(err)
		}
		added++
	}
	if err = atomicWrite(r.cfg.XrayConfig, updated, 0600); err != nil {
		return fail(err)
	}
	return map[string]any{"applied": true, "persisted": true, "added": added, "removed": removed, "total": len(users), "existing_connections": "not forcibly disconnected by standard Xray user removal"}, nil
}

func (r *Runtime) readStats(ctx context.Context) (map[string]any, error) {
	var res *statscommand.QueryStatsResponse
	var err error
	{
		if r.instance == nil {
			return nil, errors.New("core is not running")
		}
		manager, ok := r.instance.GetFeature(stats.ManagerType()).(stats.Manager)
		if !ok {
			return nil, errors.New("stats manager is unavailable")
		}
		res, err = statscommand.NewStatsServer(manager).QueryStats(ctx, &statscommand.QueryStatsRequest{Reset_: false})
	}
	if err != nil {
		return nil, err
	}
	values := map[string]int64{}
	for _, s := range res.Stat {
		values[s.Name] = s.Value
	}
	return map[string]any{"counters": values, "reset": false, "generation": r.generation, "timestamp": timeNowMillis()}, nil
}
