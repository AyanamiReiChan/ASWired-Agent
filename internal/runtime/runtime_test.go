package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"golang.org/x/net/proxy"
)

func newTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	dir := t.TempDir()
	r, e := New(config.Config{DataDir: dir, XrayConfig: filepath.Join(dir, "xray", "config.json"), XrayMode: "embedded"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	return r
}
func freePort(t *testing.T) int {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}
func command(t *testing.T, r *Runtime, action string, params map[string]any) wire.Result {
	t.Helper()
	v := r.Handle(context.Background(), wire.Command{ID: action, Action: action, Params: params})
	if v.Status != "success" {
		t.Fatalf("%s failed: %s (%v)", action, v.Error, v.Data)
	}
	return v
}

func TestEmbeddedProxyConfigurationFailureAndRestart(t *testing.T) {
	r := newTestRuntime(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ASWired proxy payload") }))
	defer target.Close()
	port := freePort(t)
	cfg := map[string]any{"log": map[string]any{"loglevel": "none"}, "stats": map[string]any{}, "policy": map[string]any{"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true}}, "inbounds": []any{map[string]any{"tag": "test-socks", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}}}
	command(t, r, "core.config.apply", map[string]any{"config": cfg})
	status := command(t, r, "core.status", nil)
	if status.Data["pid"] != os.Getpid() {
		t.Fatal("embedded core is not in Agent PID")
	}
	dialer, e := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", fmtInt(port)), nil, proxy.Direct)
	if e != nil {
		t.Fatal(e)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.Dial(network, address)
	}}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 5 * time.Second}
	request := func() {
		res, e := client.Get(target.URL)
		if e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(res.Body)
		res.Body.Close()
		if e != nil || string(body) != "ASWired proxy payload" {
			t.Fatalf("proxy data: %s %v", body, e)
		}
	}
	request()
	bad := r.Handle(context.Background(), wire.Command{ID: "bad", Action: "core.config.apply", Params: map[string]any{"config": `{"inbounds":[{"protocol":"not-a-protocol"}]}`}})
	if bad.Status != "failed" {
		t.Fatal("invalid config accepted")
	}
	request()
	command(t, r, "core.restart", nil)
	transport.CloseIdleConnections()
	request()
	stats := command(t, r, "core.stats", nil)
	if stats.Data["reset"] != false {
		t.Fatal("stats read reset counters")
	}
	command(t, r, "core.config.apply", map[string]any{"config": cfg})
	history := command(t, r, "core.config.history", nil)
	if len(history.Data["items"].([]map[string]any)) == 0 {
		t.Fatal("missing config history")
	}
}
func fmtInt(v int) string { b, _ := json.Marshal(v); return string(b) }

func TestDynamicUsersPersistWithoutRestart(t *testing.T) {
	r := newTestRuntime(t)
	cfg := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"tag": "vless", "listen": "127.0.0.1", "port": freePort(t), "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{}}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
	command(t, r, "core.config.apply", map[string]any{"config": cfg})
	generation := r.generation
	u := map[string]any{"email": "member/instance-a", "id": "11111111-1111-4111-8111-111111111111"}
	command(t, r, "core.users.sync", map[string]any{"inbound": "vless", "users": []any{u}})
	if r.generation != generation {
		t.Fatal("dynamic users restarted core")
	}
	b, e := os.ReadFile(r.cfg.XrayConfig)
	if e != nil {
		t.Fatal(e)
	}
	var out map[string]any
	json.Unmarshal(b, &out)
	clients := out["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["clients"].([]any)
	if len(clients) != 1 {
		t.Fatal("user not persisted")
	}
	command(t, r, "core.restart", nil)
	command(t, r, "core.users.sync", map[string]any{"inbound": "vless", "users": []any{}})
}

func TestCertificatePairAndManagedPaths(t *testing.T) {
	r := newTestRuntime(t)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	private := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pk}))
	result := command(t, r, "certificate.deploy", map[string]any{"name": "localhost", "certificate": cert, "private_key": private})
	if _, e = os.Stat(result.Data["private_key_path"].(string)); e != nil {
		t.Fatal(e)
	}
	for _, params := range []map[string]any{{"name": "../escape", "certificate": cert, "private_key": private}, {"name": "bad", "certificate": cert, "private_key": "not a key"}} {
		if r.Handle(context.Background(), wire.Command{Action: "certificate.deploy", Params: params}).Status != "failed" {
			t.Fatal("invalid certificate deployment succeeded")
		}
	}
}

func TestOccupiedPortAndUnknownOperation(t *testing.T) {
	r := newTestRuntime(t)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	result := command(t, r, "server.ports.check", map[string]any{"host": "127.0.0.1", "ports": []any{float64(ln.Addr().(*net.TCPAddr).Port)}})
	if result.Data["items"].([]map[string]any)[0]["available"] != false {
		t.Fatal("occupied port reported free")
	}
	if r.Handle(context.Background(), wire.Command{Action: "arbitrary.shell"}).Status != "unsupported" {
		t.Fatal("unsupported action reported success")
	}
}
