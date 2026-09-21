package runtime

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// Optional cross-repository contract test consumes actual controller output.
func TestControllerCompiledProtocols(t *testing.T) {
	dir := os.Getenv("ASWIRED_PROTOCOL_FIXTURES")
	if dir == "" {
		t.Skip("set ASWIRED_PROTOCOL_FIXTURES to controller-generated fixtures")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatal("protocol fixtures missing", err)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Config map[string]any
				Client map[string]any
				Users  []any
			}
			if err = json.Unmarshal(raw, &fixture); err != nil {
				t.Fatal(err)
			}
			server := newTestRuntime(t)
			client := newTestRuntime(t)
			port := freePort(t)
			inbound := fixture.Config["inbounds"].([]any)[0].(map[string]any)
			inbound["port"] = port
			inbound["listen"] = "127.0.0.1"
			stream := inbound["streamSettings"].(map[string]any)
			kind := inbound["protocol"].(string)
			certificatePin := ""
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "controller-agent-contract") }))
			defer target.Close()
			if stream["security"] == "tls" {
				certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
				defer certServer.Close()
				pair := certServer.TLS.Certificates[0]
				digest := sha256.Sum256(pair.Certificate[0])
				certificatePin = hex.EncodeToString(digest[:])
				key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
				if err != nil {
					t.Fatal(err)
				}
				certFile, keyFile := filepath.Join(t.TempDir(), "cert.pem"), filepath.Join(t.TempDir(), "key.pem")
				if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
					t.Fatal(err)
				}
				stream["tlsSettings"].(map[string]any)["certificates"] = []any{map[string]any{"certificateFile": certFile, "keyFile": keyFile}}
			}
			command(t, server, "core.config.apply", map[string]any{"config": fixture.Config})
			streamRaw, _ := json.Marshal(stream)
			var outboundStream map[string]any
			_ = json.Unmarshal(streamRaw, &outboundStream)
			if stream["security"] == "tls" {
				outboundStream["tlsSettings"] = map[string]any{"pinnedPeerCertSha256": certificatePin, "serverName": "example.test"}
				if kind == "hysteria" {
					outboundStream["tlsSettings"].(map[string]any)["alpn"] = []any{"h3"}
				}
			}
			c := fixture.Client
			user := fixture.Users[0].(map[string]any)
			endpoint := map[string]any{"address": "127.0.0.1", "port": port}
			settings := map[string]any{}
			switch kind {
			case "vless", "vmess":
				endpoint["users"] = []any{map[string]any{"id": c["UUID"], "encryption": "none", "security": "auto"}}
				settings["vnext"] = []any{endpoint}
			case "trojan", "shadowsocks":
				endpoint["password"] = c["Password"]
				if kind == "shadowsocks" {
					endpoint["method"] = c["Method"]
				}
				settings["servers"] = []any{endpoint}
			case "http", "socks":
				endpoint["users"] = []any{map[string]any{"user": c["Username"], "pass": c["Password"]}}
				settings["servers"] = []any{endpoint}
			case "hysteria":
				settings = map[string]any{"version": 2, "address": "127.0.0.1", "port": port}
				outboundStream["hysteriaSettings"].(map[string]any)["auth"] = user["auth"]
			default:
				t.Fatal("unknown protocol", kind)
			}
			clientPort := freePort(t)
			cfg := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"tag": "local", "listen": "127.0.0.1", "port": clientPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"protocol": kind, "settings": settings, "streamSettings": outboundStream}}}
			command(t, client, "core.config.apply", map[string]any{"config": cfg})
			request := func() bool {
				dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", fmtInt(clientPort)), nil, &net.Dialer{Timeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
				}}
				defer transport.CloseIdleConnections()
				res, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(target.URL)
				if err != nil {
					return false
				}
				defer res.Body.Close()
				body, _ := io.ReadAll(res.Body)
				return string(body) == "controller-agent-contract"
			}
			if !request() {
				t.Fatal("controller-generated configuration cannot proxy traffic")
			}
			if kind == "hysteria" {
				stats := command(t, server, "core.stats", nil).Data["counters"].(map[string]int64)
				if stats["user>>>"+user["email"].(string)+">>>traffic>>>uplink"] <= 0 {
					t.Fatal("Hysteria user accounting lost behind inbound counters")
				}
			}
			command(t, server, "core.users.sync", map[string]any{"inbound": inbound["tag"], "users": []any{}})
			command(t, client, "core.restart", nil)
			if request() {
				t.Fatal("revoked subscription still connects")
			}
			command(t, server, "core.users.sync", map[string]any{"inbound": inbound["tag"], "users": fixture.Users})
			command(t, client, "core.restart", nil)
			if !request() {
				t.Fatal("subscription restore failed")
			}
		})
	}
}
