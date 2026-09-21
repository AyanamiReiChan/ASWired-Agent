package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func writeConfig(path string, value map[string]any) error {
	if path == "" {
		return errors.New("configuration file path is unavailable")
	}
	info, e := os.Lstat(path)
	if e == nil && !info.Mode().IsRegular() {
		return errors.New("configuration path must be a regular file")
	}
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".aswired-identity-*")
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
func RotateCredentials(path, token, agentToken, previous string, expires int64) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	var value map[string]any
	if e = json.Unmarshal(b, &value); e != nil {
		return e
	}
	value["token"] = token
	value["agent_token"] = agentToken
	value["previous_agent_token"] = previous
	value["previous_token_expires_at"] = expires
	return writeConfig(path, value)
}

func SaveConnection(path, mode, listen string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var value map[string]any
	if err = json.Unmarshal(b, &value); err != nil {
		return err
	}
	value["connection_mode"] = mode
	value["listen_address"] = listen
	return writeConfig(path, value)
}
func PairHome(ctx context.Context, origin, code, path string) error {
	u, e := url.Parse(origin)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return errors.New("pair-url must be a controller origin without path, credentials or query")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("pairing requires HTTPS; HTTP is permitted only for a loopback test controller")
		}
	}
	if strings.TrimSpace(code) == "" || len(code) > 256 || strings.ContainsAny(code, "\r\n\t") {
		return errors.New("invalid pairing code")
	}
	var local map[string]any
	b, e := os.ReadFile(path)
	if e == nil {
		e = json.Unmarshal(b, &local)
	} else if os.IsNotExist(e) {
		local = map[string]any{}
		e = nil
	}
	if e != nil {
		return e
	}
	payload, _ := json.Marshal(map[string]any{"code": code})
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(origin, "/")+"/api/home/pair", bytes.NewReader(payload))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("pairing redirects are forbidden") }}
	res, e := client.Do(req)
	if e != nil {
		return errors.New("pairing controller request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("pairing was rejected or the one-use code expired")
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, 65537))
	if e != nil || len(raw) > 65536 {
		return errors.New("invalid pairing response")
	}
	var response struct {
		Config map[string]any `json:"config"`
	}
	if json.Unmarshal(raw, &response) != nil || response.Config == nil {
		return errors.New("pairing response lacks configuration")
	}
	returned, _ := response.Config["master_url"].(string)
	master, e := url.Parse(returned)
	if e != nil || master.Scheme != u.Scheme || !strings.EqualFold(master.Host, u.Host) || strings.Trim(master.Path, "/") != "" || master.User != nil || master.RawQuery != "" || master.Fragment != "" {
		return errors.New("pairing response attempted to change controller origin")
	}
	for _, key := range []string{"server_id", "token", "agent_token", "master_public_key", "master_url"} {
		value, ok := response.Config[key].(string)
		if !ok || value == "" {
			return errors.New("pairing response contains an incomplete identity")
		}
		local[key] = value
	}
	local["role"] = "speedtest"
	local["source_mode"] = "home"
	local["connection_mode"] = "websocket"
	local["xray_mode"] = "embedded"
	delete(local, "previous_agent_token")
	delete(local, "previous_token_expires_at")
	if local["data_dir"] == nil {
		abs, e := filepath.Abs(filepath.Join(filepath.Dir(path), "home-data"))
		if e != nil {
			return e
		}
		local["data_dir"] = abs
	}
	b, _ = json.Marshal(local)
	var candidate Config
	if e = json.Unmarshal(b, &candidate); e != nil {
		return e
	}
	candidate.DataDir, e = filepath.Abs(candidate.DataDir)
	if e != nil {
		return e
	}
	if e = candidate.Validate(false); e != nil {
		return e
	}
	return writeConfig(path, local)
}
