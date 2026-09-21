package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
)

type Config struct {
	ConfigPath           string `json:"-"`
	Role                 string `json:"role"`
	ServerID             string `json:"server_id"`
	MasterURL            string `json:"master_url"`
	Token                string `json:"token"`
	AgentToken           string `json:"agent_token"`
	PreviousAgentToken   string `json:"previous_agent_token,omitempty"`
	PreviousTokenExpires int64  `json:"previous_token_expires_at,omitempty"`
	MasterPublicKey      string `json:"master_public_key"`
	ConnectionMode       string `json:"connection_mode"`
	ListenAddress        string `json:"listen_address,omitempty"`
	XrayMode             string `json:"xray_mode"`
	DataDir              string `json:"data_dir"`
	XrayConfig           string `json:"xray_config"`
	NginxBinary          string `json:"nginx_binary"`
	NginxConfig          string `json:"nginx_config"`
	WireGuardQuickBinary string `json:"wg_quick_binary"`
	WireGuardBinary      string `json:"wg_binary"`
	IPBinary             string `json:"ip_binary"`
	MihomoBinary         string `json:"mihomo_binary,omitempty"`
	MihomoVersion        string `json:"mihomo_version,omitempty"`
	MihomoSHA256         string `json:"mihomo_sha256,omitempty"`
	ObservationInterval  int    `json:"observation_interval,omitempty"` // Legacy input; host monitoring belongs to Komari.
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err = json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("read agent configuration: %w", err)
	}
	c.ConfigPath, err = filepath.Abs(path)
	if err != nil {
		return c, err
	}
	if c.ConnectionMode == "" {
		c.ConnectionMode = "websocket"
	}
	if c.ListenAddress == "" {
		c.ListenAddress = "0.0.0.0:23889"
	}
	if c.XrayMode == "" {
		c.XrayMode = "embedded"
	}
	if c.DataDir == "" {
		c.DataDir = filepath.Join(filepath.Dir(path), "data")
	}
	c.DataDir, err = filepath.Abs(c.DataDir)
	if err != nil {
		return c, err
	}
	if c.XrayConfig == "" {
		c.XrayConfig = filepath.Join(c.DataDir, "xray", "config.json")
	}
	if c.NginxBinary == "" {
		c.NginxBinary = "nginx"
	}
	if c.WireGuardQuickBinary == "" {
		c.WireGuardQuickBinary = "wg-quick"
	}
	if c.WireGuardBinary == "" {
		c.WireGuardBinary = "wg"
	}
	if c.IPBinary == "" {
		c.IPBinary = "ip"
	}
	return c, nil
}

func (c Config) Validate(standalone bool) error {
	if c.XrayMode != "embedded" {
		return errors.New("only embedded Xray is supported; set xray_mode to embedded and reinstall")
	}
	if !ValidConnectionMode(c.ConnectionMode) {
		return errors.New("connection_mode must be auto, websocket, http or pull")
	}
	if c.ConnectionMode == "http" || c.ConnectionMode == "auto" {
		if _, _, err := net.SplitHostPort(c.ListenAddress); err != nil {
			return fmt.Errorf("listen_address: %w", err)
		}
		if c.AgentToken == "" && !standalone {
			return errors.New("agent_token is required for HTTP management")
		}
	}
	if c.DataDir == "" || !filepath.IsAbs(c.DataDir) {
		return errors.New("data_dir must resolve to an absolute path")
	}
	if standalone {
		return nil
	}
	u, err := url.Parse(c.MasterURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("master_url must be an HTTP(S) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("master_url cannot include credentials, query or fragment")
	}
	if c.ServerID == "" || c.Token == "" {
		return errors.New("server_id and server token are required")
	}
	k, err := base64.StdEncoding.DecodeString(c.MasterPublicKey)
	if err != nil {
		k, err = base64.RawStdEncoding.DecodeString(c.MasterPublicKey)
	}
	if err != nil {
		k, err = base64.RawURLEncoding.DecodeString(c.MasterPublicKey)
	}
	if err != nil || len(k) != 32 {
		return errors.New("master_public_key must be the pinned 32-byte X25519 public key")
	}
	return nil
}

func ValidConnectionMode(mode string) bool {
	return mode == "auto" || mode == "websocket" || mode == "http" || mode == "pull"
}
