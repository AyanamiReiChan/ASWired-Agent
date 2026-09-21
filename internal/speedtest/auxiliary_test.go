package speedtest

import (
	"bytes"
	"context"
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

func TestRealAuxiliaryAnyTLSAndSnellThroughAccountedXrayBridge(t *testing.T) {
	binary := os.Getenv("ASWIRED_TEST_MIHOMO")
	if binary == "" {
		t.Skip("set pinned ASWIRED_TEST_MIHOMO for real auxiliary protocol integration")
	}
	for _, kind := range []string{"anytls", "snell3", "snell4"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			cfg := config.Config{DataDir: dir, XrayConfig: filepath.Join(dir, "xray.json"), XrayMode: "embedded", MihomoBinary: binary, MihomoVersion: "v1.19.31", MihomoSHA256: "1fa8055e03596fc35167f70e9ecd1890517d38d960a39177445746a1b0defc2b"}
			core, e := agentruntime.New(cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer core.Close()
			call := func(action string, params map[string]any) wire.Result {
				t.Helper()
				r := core.Handle(context.Background(), wire.Command{Action: action, Params: params})
				if r.Status != "success" {
					t.Fatalf("%s: %s %+v", action, r.Error, r.Data)
				}
				return r
			}
			port := func() int {
				l, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				p := l.Addr().(*net.TCPAddr).Port
				l.Close()
				return p
			}
			bridgePort, listenPort := port(), port()
			idA, idB := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
			call("core.config.apply", map[string]any{"config": map[string]any{"log": map[string]any{"loglevel": "none"}, "stats": map[string]any{}, "policy": map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}}}, "inbounds": []any{map[string]any{"tag": "private-bridge", "listen": "127.0.0.1", "port": bridgePort, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"email": "instance-a", "id": idA}, map[string]any{"email": "instance-b", "id": idB}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}})
			call("core.policy.apply", map[string]any{"policies": []any{map[string]any{"user_id": "same-user", "emails": []any{"instance-a", "instance-b"}, "bytes_per_second": 262144, "direction": "download"}}})
			originalGeneration := call("core.stats", nil).Data["generation"]
			user := func(email, password, id string) map[string]any {
				return map[string]any{"email": email, "password": password, "bridge": map[string]any{"port": bridgePort, "id": id}}
			}
			uA, uB := user("instance-a", "first-password", idA), user("instance-b", "second-password", idB)
			listener := map[string]any{"name": "aux-test", "type": "anytls", "listen": "127.0.0.1", "port": listenPort, "users": []any{uA}}
			version := 0
			if kind == "anytls" {
				cert, key := localProtocolCertificate(t)
				listener["certificate"] = strings.Join(cert, "\n")
				listener["private_key"] = strings.Join(key, "\n")
			} else {
				listener["type"] = "snell"
				version = 3
				if kind == "snell4" {
					version = 4
				}
				listener["version"] = version
			}
			call("mihomo.config.apply", map[string]any{"listeners": []any{listener}})
			if !core.Capabilities()["mihomo_auxiliary"] {
				t.Fatal("configured and verified auxiliary capability missing")
			}
			if kind == "anytls" {
				call("mihomo.users.sync", map[string]any{"inbound": "aux-test", "users": []any{uA, uB}})
			}
			runner, e := New(Config{Binary: binary, SHA256: cfg.MihomoSHA256, Version: cfg.MihomoVersion, DataDir: filepath.Join(dir, "speedtest"), SourceID: "real-auxiliary-test"})
			if e != nil {
				t.Fatal(e)
			}
			var count atomic.Int64
			payload := bytes.Repeat([]byte("real-auxiliary"), 8<<10)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { count.Add(1); w.Write(payload) }))
			defer target.Close()
			measure := func(password string) wire.Result {
				node := map[string]any{"type": "anytls", "server": "127.0.0.1", "port": listenPort, "password": password, "sni": "localhost", "skip-cert-verify": true}
				if kind != "anytls" {
					node = map[string]any{"type": "snell", "server": "127.0.0.1", "port": listenPort, "psk": password, "version": version}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				return runner.Handle(ctx, wire.Command{Action: "speedtest.run", Params: map[string]any{"node": node, "url": target.URL, "duration_seconds": float64(3)}})
			}
			assertTransfer := func(password string) {
				t.Helper()
				r := measure(password)
				if r.Status != "success" {
					t.Fatalf("%s actual bridge failed: %s %+v", kind, r.Error, r.Data)
				}
				if r.Data["download_bytes"].(int64) <= 0 || r.Data["download_mbps"].(float64) > 5 {
					t.Fatalf("missing payload or shared Xray policy bypass: %+v", r.Data)
				}
			}
			assertTransfer("first-password")
			if kind == "anytls" {
				assertTransfer("second-password")
			}
			stats := call("core.stats", nil)
			if stats.Data["generation"] != originalGeneration {
				t.Fatal("auxiliary reload restarted Xray accounting generation")
			}
			for _, email := range []string{"instance-a", "instance-b"} {
				if email == "instance-b" && kind != "anytls" {
					continue
				}
				if stats.Data["counters"].(map[string]int64)["user>>>"+email+">>>traffic>>>downlink"] <= 0 {
					t.Fatalf("no real bridge user counter %s", email)
				}
			}

			occupied, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			bad := map[string]any{}
			for k, v := range listener {
				bad[k] = v
			}
			bad["port"] = occupied.Addr().(*net.TCPAddr).Port
			pid := call("mihomo.status", nil).Data["pid"]
			failure := core.Handle(context.Background(), wire.Command{Action: "mihomo.config.apply", Params: map[string]any{"listeners": []any{bad}}})
			occupied.Close()
			if failure.Status != "failed" || call("mihomo.status", nil).Data["pid"] != pid {
				t.Fatal("invalid candidate disrupted current auxiliary service")
			}
			assertTransfer("first-password")
			remaining := []any{}
			revokedPassword := "first-password"
			if kind == "anytls" {
				remaining = []any{uA}
				revokedPassword = "second-password"
			}
			call("mihomo.users.sync", map[string]any{"inbound": "aux-test", "users": remaining})
			before := count.Load()
			if r := measure(revokedPassword); r.Status != "failed" {
				t.Fatal("revoked auxiliary password accepted")
			}
			if count.Load() != before {
				t.Fatal("revocation fell back directly or reached bridge")
			}
			if kind == "anytls" {
				assertTransfer("first-password")
				core.Close()
				restored, e := agentruntime.New(cfg)
				if e != nil {
					t.Fatal(e)
				}
				defer restored.Close()
				if e = restored.Start(context.Background()); e != nil {
					t.Fatal(e)
				}
				core = restored
				assertTransfer("first-password")
			}
		})
	}
}
