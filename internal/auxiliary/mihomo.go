package auxiliary

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/mihomoapi"
	"github.com/xtls/xray-core/common/uuid"
)

type Config struct {
	Binary, Version, SHA256, DataDir string
	ValidateUser                     func(string) error
}
type Bridge struct {
	Port int    `json:"port"`
	ID   string `json:"id"`
}
type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Bridge   Bridge `json:"bridge"`
}
type Listener struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Listen        string `json:"listen"`
	Port          int    `json:"port"`
	Users         []User `json:"users"`
	Certificate   string `json:"certificate,omitempty"`
	PrivateKey    string `json:"private_key,omitempty"`
	Version       int    `json:"version,omitempty"`
	UDP           bool   `json:"udp,omitempty"`
	PaddingScheme string `json:"padding_scheme,omitempty"`
}
type state struct {
	Enabled   bool       `json:"enabled"`
	Listeners []Listener `json:"listeners"`
}
type Manager struct {
	mu                                       sync.Mutex
	cfg                                      Config
	desired                                  state
	process                                  *exec.Cmd
	done                                     chan error
	api, secret, generation, validationError string
}

func New(cfg Config) (*Manager, error) {
	m := &Manager{cfg: cfg}
	if e := os.MkdirAll(filepath.Join(cfg.DataDir, "mihomo"), 0700); e != nil {
		return nil, e
	}
	b, e := os.ReadFile(m.path("state.json"))
	if e == nil {
		if e = json.Unmarshal(b, &m.desired); e != nil {
			return nil, errors.New("invalid persisted mihomo state")
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if e = m.verify(); e != nil {
		m.validationError = e.Error()
	}
	return m, nil
}
func (m *Manager) path(name string) string { return filepath.Join(m.cfg.DataDir, "mihomo", name) }
func (m *Manager) Available() bool         { m.mu.Lock(); defer m.mu.Unlock(); return m.validationError == "" }
func (m *Manager) verify() error {
	if m.cfg.Binary == "" || m.cfg.Version == "" || len(m.cfg.SHA256) != 64 {
		return errors.New("optional mihomo binary, exact version and SHA256 are not configured")
	}
	f, e := os.Open(m.cfg.Binary)
	if e != nil {
		return errors.New("configured mihomo executable is unavailable")
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	f.Close()
	if e != nil || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), m.cfg.SHA256) {
		return errors.New("mihomo executable SHA256 mismatch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, m.cfg.Binary, "-v")
	hideProcess(c)
	b, e := c.Output()
	if e != nil {
		return errors.New("cannot verify mihomo version")
	}
	for _, field := range strings.Fields(string(b)) {
		if field == m.cfg.Version {
			return nil
		}
	}
	return errors.New("mihomo version mismatch")
}
func safeToken(value string) bool {
	if value == "" || len(value) > 180 {
		return false
	}
	for _, c := range value {
		if c < 33 || c > 126 || strings.ContainsRune(",()\"'\\", c) {
			return false
		}
	}
	return true
}
func (m *Manager) material(value string) (string, error) {
	if strings.Contains(value, "-----BEGIN ") {
		return value, nil
	}
	abs, e := filepath.Abs(value)
	if e != nil {
		return "", e
	}
	rel, e := filepath.Rel(filepath.Join(m.cfg.DataDir, "certificates"), abs)
	if value == "" || e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("TLS material must be PEM or a managed certificate path")
	}
	info, e := os.Lstat(abs)
	if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return "", errors.New("invalid managed TLS file")
	}
	b, e := os.ReadFile(abs)
	return string(b), e
}
func (m *Manager) validate(list []Listener) error {
	if len(list) > 256 {
		return errors.New("at most 256 auxiliary listeners are allowed")
	}
	names, users, addresses := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, l := range list {
		if !safeToken(l.Name) || names[l.Name] {
			return errors.New("listener names must be unique safe identifiers")
		}
		names[l.Name] = true
		if l.Type != "anytls" && l.Type != "snell" {
			return errors.New("auxiliary adapter supports only anytls and tested Snell versions")
		}
		if net.ParseIP(l.Listen) == nil || l.Port < 1 || l.Port > 65535 {
			return errors.New("listener requires an explicit IP and valid port")
		}
		address := net.JoinHostPort(l.Listen, fmt.Sprint(l.Port))
		if addresses[address] {
			return errors.New("duplicate listener address")
		}
		addresses[address] = true
		if len(l.Users) > 10000 {
			return errors.New("too many listener users")
		}
		if l.Type == "snell" && (len(l.Users) > 1 || (l.Version != 3 && l.Version != 4)) {
			return errors.New("Snell requires at most one user per listener and an explicitly tested version 3 or 4")
		}
		if l.UDP {
			return errors.New("auxiliary bridge UDP is not yet supported; use TCP or the native Xray protocols")
		}
		if len(l.PaddingScheme) > 16384 {
			return errors.New("padding scheme too large")
		}
		for _, u := range l.Users {
			if m.cfg.ValidateUser != nil {
				if e := m.cfg.ValidateUser(u.Email); e != nil {
					return e
				}
			}
			if !safeToken(u.Email) || users[u.Email] || u.Password == "" || len(u.Password) > 4096 {
				return errors.New("auxiliary users require globally unique safe emails and passwords")
			}
			users[u.Email] = true
			if u.Bridge.Port < 1 || u.Bridge.Port > 65535 {
				return errors.New("user requires a local Xray bridge port")
			}
			if parsed, e := uuid.ParseString(u.Bridge.ID); e != nil || len(u.Bridge.ID) != 36 || parsed.String() != strings.ToLower(u.Bridge.ID) {
				return errors.New("user requires a valid local VLESS bridge UUID")
			}
		}
		if l.Type == "anytls" && len(l.Users) > 0 {
			cert, e := m.material(l.Certificate)
			if e != nil {
				return e
			}
			key, e := m.material(l.PrivateKey)
			if e != nil {
				return e
			}
			if _, e = tls.X509KeyPair([]byte(cert), []byte(key)); e != nil {
				return errors.New("AnyTLS certificate and private key do not match")
			}
		}
	}
	return nil
}
func randomID() string {
	var b [24]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func (m *Manager) configuration(list []Listener, api, secret string) ([]byte, error) {
	listeners, proxies, rules := []any{}, []any{}, []string{}
	for _, l := range list {
		if len(l.Users) == 0 {
			continue
		}
		item := map[string]any{"name": l.Name, "type": l.Type, "listen": l.Listen, "port": l.Port}
		usermap := map[string]string{}
		for _, u := range l.Users {
			h := sha256.Sum256([]byte(u.Email))
			name := "aswired-bridge-" + hex.EncodeToString(h[:12])
			proxies = append(proxies, map[string]any{"name": name, "type": "vless", "server": "127.0.0.1", "port": u.Bridge.Port, "uuid": u.Bridge.ID, "network": "tcp", "tls": false, "udp": false})
			usermap[u.Email] = u.Password
			if l.Type == "snell" {
				item["proxy"] = name
			} else {
				rules = append(rules, "IN-USER,"+u.Email+","+name)
			}
		}
		if l.Type == "anytls" {
			cert, e := m.material(l.Certificate)
			if e != nil {
				return nil, e
			}
			key, e := m.material(l.PrivateKey)
			if e != nil {
				return nil, e
			}
			item["users"] = usermap
			item["certificate"] = cert
			item["private-key"] = key
			if l.PaddingScheme != "" {
				item["padding-scheme"] = l.PaddingScheme
			}
		} else {
			item["psk"] = l.Users[0].Password
			item["version"] = l.Version
			item["udp"] = false
		}
		listeners = append(listeners, item)
	}
	rules = append(rules, "MATCH,REJECT")
	return json.Marshal(map[string]any{"mode": "rule", "log-level": "error", "ipv6": true, "allow-lan": true, "bind-address": "127.0.0.1", "external-controller": api, "secret": secret, "external-controller-cors": map[string]any{"allow-origins": []string{}}, "dns": map[string]any{"enable": false}, "listeners": listeners, "proxies": proxies, "rules": rules})
}
func safeWrite(path string, b []byte) error {
	if info, e := os.Lstat(path); e == nil && !info.Mode().IsRegular() {
		return errors.New("refusing non-regular auxiliary file")
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".write-*")
	if e != nil {
		return e
	}
	temp := f.Name()
	defer os.Remove(temp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return os.Rename(temp, path)
}
func (m *Manager) save(s state) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return safeWrite(m.path("state.json"), b)
}
func (m *Manager) running() bool {
	if m.process == nil {
		return false
	}
	select {
	case <-m.done:
		return false
	default:
		return true
	}
}
func (m *Manager) stop() {
	if m.process != nil {
		if m.running() {
			_ = m.process.Process.Kill()
			<-m.done
		}
		m.process = nil
		m.done = nil
	}
	m.api = ""
	m.secret = ""
}
func (m *Manager) apiRequest(ctx context.Context, path string) error {
	req, e := http.NewRequestWithContext(ctx, "GET", "http://"+m.api+path, nil)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+m.secret)
	client := http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	res, e := client.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("local mihomo API rejected authentication")
	}
	return nil
}
func (m *Manager) preflight(ctx context.Context, list []Listener) error {
	if e := m.verify(); e != nil {
		m.validationError = e.Error()
		return e
	}
	m.validationError = ""
	if e := m.validate(list); e != nil {
		return e
	}
	b, e := m.configuration(list, "127.0.0.1:1", randomID())
	if e != nil {
		return e
	}
	path := m.path("candidate.json")
	if e = safeWrite(path, b); e != nil {
		return e
	}
	defer os.Remove(path)
	check, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c := exec.CommandContext(check, m.cfg.Binary, "-t", "-d", m.path(""), "-f", path)
	hideProcess(c)
	if e = c.Run(); e != nil {
		return errors.New("mihomo rejected candidate configuration")
	}
	current := map[string]bool{}
	if m.running() {
		for _, l := range m.desired.Listeners {
			if len(l.Users) > 0 {
				current[net.JoinHostPort(l.Listen, fmt.Sprint(l.Port))] = true
			}
		}
	}
	for _, l := range list {
		if len(l.Users) == 0 {
			continue
		}
		address := net.JoinHostPort(l.Listen, fmt.Sprint(l.Port))
		if current[address] {
			continue
		}
		ln, e := net.Listen("tcp", address)
		if e != nil {
			return fmt.Errorf("auxiliary listener %s port is unavailable", l.Name)
		}
		ln.Close()
	}
	return nil
}
func (m *Manager) launch(ctx context.Context, list []Listener) error {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	api := ln.Addr().String()
	ln.Close()
	secret := randomID()
	b, e := m.configuration(list, api, secret)
	if e != nil {
		return e
	}
	if e = safeWrite(m.path("config.json"), b); e != nil {
		return e
	}
	c := exec.Command(m.cfg.Binary, "-d", m.path(""), "-f", m.path("config.json"))
	hideProcess(c)
	if e = c.Start(); e != nil {
		return errors.New("mihomo process did not start")
	}
	release, e := ownChild(c)
	if e != nil {
		_ = c.Process.Kill()
		_ = c.Wait()
		return errors.New("could not bind auxiliary process lifetime to Agent")
	}
	done := make(chan error, 1)
	go func() { defer release(); done <- c.Wait(); close(done) }()
	m.process = c
	m.done = done
	m.api = api
	m.secret = secret
	m.generation = randomID()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if !m.running() {
			m.stop()
			return errors.New("mihomo exited before readiness")
		}
		if ctx.Err() != nil {
			m.stop()
			return ctx.Err()
		}
		if m.apiRequest(ctx, "/version") == nil {
			ready := true
			for _, l := range list {
				if len(l.Users) == 0 {
					continue
				}
				for _, u := range l.Users {
					h := sha256.Sum256([]byte(u.Email))
					if m.apiRequest(ctx, "/proxies/aswired-bridge-"+hex.EncodeToString(h[:12])) != nil {
						ready = false
						break
					}
				}
				if !ready {
					break
				}
				host := l.Listen
				if host == "0.0.0.0" {
					host = "127.0.0.1"
				}
				if host == "::" {
					host = "::1"
				}
				c, e := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(l.Port)), 100*time.Millisecond)
				if e != nil {
					ready = false
					break
				}
				c.Close()
			}
			if ready {
				if e = mihomoapi.AwaitConfiguration(ctx, m.api, m.secret); e != nil {
					m.stop()
					return e
				}
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	m.stop()
	return errors.New("mihomo local API/listeners did not become ready")
}
func (m *Manager) apply(ctx context.Context, list []Listener) (map[string]any, error) {
	if len(list) == 0 {
		next := state{Enabled: false, Listeners: []Listener{}}
		if err := m.save(next); err != nil {
			return nil, err
		}
		m.stop()
		m.desired = next
		result := m.snapshot()
		result["applied"] = true
		return result, nil
	}
	if e := m.preflight(ctx, list); e != nil {
		return nil, e
	}
	old := m.desired
	wasRunning := m.running()
	m.stop()
	recover := func(cause error) (map[string]any, error) {
		m.stop()
		var rollback error
		if wasRunning {
			rollback = m.launch(context.Background(), old.Listeners)
		}
		return map[string]any{"applied": false, "rollback_succeeded": rollback == nil, "rollback_error": fmt.Sprint(rollback)}, cause
	}
	if e := m.launch(ctx, list); e != nil {
		return recover(e)
	}
	next := state{Enabled: true, Listeners: list}
	if e := m.save(next); e != nil {
		return recover(e)
	}
	m.desired = next
	out := m.snapshot()
	out["applied"] = true
	out["reload_mode"] = "verified_process_restart"
	out["existing_connections"] = "auxiliary sessions reconnect; the Xray accounting core is not restarted"
	return out, nil
}
func (m *Manager) Apply(ctx context.Context, raw any) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, e := json.Marshal(raw)
	if e != nil {
		return nil, e
	}
	if len(b) > 8<<20 {
		return nil, errors.New("auxiliary configuration exceeds 8 MiB")
	}
	var list []Listener
	if e = json.Unmarshal(b, &list); e != nil || list == nil {
		return nil, errors.New("listeners array required; use [] to remove all")
	}
	return m.apply(ctx, list)
}
func (m *Manager) Sync(ctx context.Context, name string, raw any) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, e := json.Marshal(raw)
	if e != nil {
		return nil, e
	}
	var users []User
	if e = json.Unmarshal(b, &users); e != nil || users == nil {
		return nil, errors.New("users array required")
	}
	list := append([]Listener(nil), m.desired.Listeners...)
	for i := range list {
		if list[i].Name == name {
			list[i].Users = users
			return m.apply(ctx, list)
		}
	}
	return nil, errors.New("auxiliary inbound does not exist")
}
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running() {
		return nil
	}
	if !m.desired.Enabled {
		return nil
	}
	if e := m.preflight(ctx, m.desired.Listeners); e != nil {
		return e
	}
	return m.launch(ctx, m.desired.Listeners)
}
func (m *Manager) Activate(ctx context.Context) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.apply(ctx, m.desired.Listeners)
}
func (m *Manager) Stop() (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.desired
	next.Enabled = false
	if e := m.save(next); e != nil {
		return nil, e
	}
	m.stop()
	m.desired = next
	return m.snapshot(), nil
}
func (m *Manager) Close() { m.mu.Lock(); defer m.mu.Unlock(); m.stop() }
func (m *Manager) snapshot() map[string]any {
	items := []any{}
	for _, l := range m.desired.Listeners {
		items = append(items, map[string]any{"name": l.Name, "type": l.Type, "listen": l.Listen, "port": l.Port, "users": len(l.Users), "enabled": len(l.Users) > 0, "version": l.Version})
	}
	pid := 0
	if m.running() {
		pid = m.process.Process.Pid
	}
	return map[string]any{"running": m.running(), "enabled": m.desired.Enabled, "pid": pid, "generation": m.generation, "version": m.cfg.Version, "listeners": items, "available": m.validationError == "", "error": m.validationError, "stats_scope": "xray_bridge", "original_client_ip": false, "reload_mode": "verified_process_restart"}
}
func (m *Manager) Snapshot() map[string]any { m.mu.Lock(); defer m.mu.Unlock(); return m.snapshot() }
func (m *Manager) Configuration() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _ := json.Marshal(m.desired)
	var copy map[string]any
	json.NewDecoder(bytes.NewReader(b)).Decode(&copy)
	return copy
}
func (m *Manager) BridgeEmails() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	if m.desired.Enabled {
		for _, l := range m.desired.Listeners {
			for _, u := range l.Users {
				out[u.Email] = true
			}
		}
	}
	return out
}
