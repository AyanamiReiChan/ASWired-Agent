package speedtest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	agentruntime "github.com/AyanamiReiChan/ASWired-Agent/internal/runtime"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
)

func localProtocolCertificate(t *testing.T) ([]string, []string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return strings.Split(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "\n"), strings.Split(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), "\n")
}

func TestRealMihomoHysteriaAndShadowsocksDynamicUsers(t *testing.T) {
	binary := os.Getenv("ASWIRED_TEST_MIHOMO")
	if binary == "" {
		t.Skip("set ASWIRED_TEST_MIHOMO to the pinned mihomo v1.19.31 artifact")
	}
	for _, kind := range []string{"hysteria", "shadowsocks"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			core, e := agentruntime.New(config.Config{DataDir: dir, XrayConfig: filepath.Join(dir, "xray.json"), XrayMode: "embedded"})
			if e != nil {
				t.Fatal(e)
			}
			defer core.Close()
			call := func(action string, params map[string]any) wire.Result {
				t.Helper()
				r := core.Handle(context.Background(), wire.Command{ID: action, Action: action, Params: params})
				if r.Status != "success" {
					t.Fatalf("%s: %s %+v", action, r.Error, r.Data)
				}
				return r
			}
			var port int
			if kind == "hysteria" {
				ln, e := net.ListenPacket("udp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				port = ln.LocalAddr().(*net.UDPAddr).Port
				ln.Close()
			} else {
				ln, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				port = ln.Addr().(*net.TCPAddr).Port
				ln.Close()
			}
			credential := func(email, password string) map[string]any {
				m := map[string]any{"email": email, "level": float64(0)}
				if kind == "hysteria" {
					m["auth"] = password
				} else {
					m["method"] = "aes-128-gcm"
					m["password"] = password
				}
				return m
			}
			first := credential("physical-user.instance-a", "first-private-password")
			second := credential("physical-user.instance-b", "second-private-password")
			settings := map[string]any{"clients": []any{first}}
			entry := map[string]any{"tag": "managed", "listen": "127.0.0.1", "port": port, "protocol": kind, "settings": settings}
			if kind == "hysteria" {
				cert, key := localProtocolCertificate(t)
				settings["version"] = 2
				entry["streamSettings"] = map[string]any{"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2}, "tlsSettings": map[string]any{"alpn": []string{"h3"}, "certificates": []any{map[string]any{"certificate": cert, "key": key}}}}
			} else {
				settings["method"] = "aes-128-gcm"
				settings["network"] = "tcp,udp"
			}
			call("core.config.apply", map[string]any{"config": map[string]any{"log": map[string]any{"loglevel": "none"}, "stats": map[string]any{}, "policy": map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}}}, "inbounds": []any{entry}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}})
			generation := call("core.stats", nil).Data["generation"]
			call("core.users.sync", map[string]any{"inbound": "managed", "users": []any{first, second}})
			call("core.policy.apply", map[string]any{"policies": []any{map[string]any{"user_id": "physical-user", "emails": []any{first["email"], second["email"]}, "bytes_per_second": 262144, "direction": "download", "connection_limit": 8}}})
			runner, e := New(Config{Binary: binary, SHA256: "1fa8055e03596fc35167f70e9ecd1890517d38d960a39177445746a1b0defc2b", Version: "v1.19.31", DataDir: filepath.Join(dir, "home"), SourceID: "protocol-fixture"})
			if e != nil {
				t.Fatal(e)
			}
			var requests atomic.Int64
			payload := bytes.Repeat([]byte("proxy-data"), 16<<10)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.Write(payload) }))
			defer target.Close()
			measure := func(password string) wire.Result {
				node := map[string]any{"name": "test", "server": "127.0.0.1", "port": port, "password": password}
				if kind == "hysteria" {
					node["type"] = "hysteria2"
					node["sni"] = "localhost"
					node["skip-cert-verify"] = true
				} else {
					node["type"] = "ss"
					node["cipher"] = "aes-128-gcm"
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				return runner.Handle(ctx, wire.Command{ID: password, Action: "speedtest.run", Params: map[string]any{"node": node, "url": target.URL, "duration_seconds": float64(1), "parallel": float64(1)}})
			}
			for _, password := range []string{"first-private-password", "second-private-password"} {
				r := measure(password)
				if r.Status != "success" {
					t.Fatalf("real %s transfer: %s %+v", kind, r.Error, r.Data)
				}
				if r.Data["download_bytes"].(int64) <= 0 {
					t.Fatal("no authenticated payload transferred")
				}
				if r.Data["download_mbps"].(float64) > 5 {
					t.Fatalf("authenticated %s traffic bypassed the 256 KiB/s policy: %.2f Mbps", kind, r.Data["download_mbps"])
				}
			}
			stats := call("core.stats", nil)
			if stats.Data["generation"] != generation {
				t.Fatal("dynamic sync restarted core")
			}
			for _, email := range []string{"physical-user.instance-a", "physical-user.instance-b"} {
				if stats.Data["counters"].(map[string]int64)["user>>>"+email+">>>traffic>>>downlink"] <= 0 {
					t.Fatalf("missing actual counter for %s", email)
				}
			}
			call("core.users.sync", map[string]any{"inbound": "managed", "users": []any{first}})
			before := requests.Load()
			revoked := measure("second-private-password")
			if revoked.Status != "failed" {
				t.Fatalf("revoked %s credential accepted", kind)
			}
			if requests.Load() != before {
				t.Fatal("revoked credential or direct fallback reached target")
			}
			if r := measure("first-private-password"); r.Status != "success" {
				t.Fatalf("retained credential stopped working: %s", r.Error)
			}
			if call("core.stats", nil).Data["generation"] != generation {
				t.Fatal("removal restarted core")
			}
		})
	}
}
