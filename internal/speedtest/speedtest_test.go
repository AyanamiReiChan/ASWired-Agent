package speedtest

import (
	"bytes"
	"context"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	agentruntime "github.com/AyanamiReiChan/ASWired-Agent/internal/runtime"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestRealMihomoProxyMeasurementAndNoDirectFallback(t *testing.T) {
	binary := os.Getenv("ASWIRED_TEST_MIHOMO")
	if binary == "" {
		t.Skip("set ASWIRED_TEST_MIHOMO to pinned v1.19.31 Windows amd64 compatible artifact for integration test")
	}
	root := t.TempDir()
	runtime, e := agentruntime.New(config.Config{DataDir: root, XrayConfig: filepath.Join(root, "xray.json"), XrayMode: "embedded"})
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	result := runtime.Handle(context.Background(), wire.Command{ID: "config", Action: "core.config.apply", Params: map[string]any{"config": map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"tag": "test", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}}})
	if result.Status != "success" {
		t.Fatal(result.Error)
	}
	hash, version := os.Getenv("ASWIRED_TEST_MIHOMO_SHA256"), os.Getenv("ASWIRED_TEST_MIHOMO_VERSION")
	if hash == "" {
		hash = "1fa8055e03596fc35167f70e9ecd1890517d38d960a39177445746a1b0defc2b"
	}
	if version == "" {
		version = "v1.19.31"
	}
	r, e := New(Config{Binary: binary, SHA256: hash, Version: version, DataDir: filepath.Join(root, "home"), SourceID: "home-test"})
	if e != nil {
		t.Fatal(e)
	}
	var requests atomic.Int64
	var downloads atomic.Int64
	payload := bytes.Repeat([]byte("x"), 16<<10)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path == "/ip" {
			w.Write([]byte(`{"ip":"203.0.113.7"}`))
			return
		}
		if request.Method == http.MethodGet {
			downloads.Add(1)
		}
		w.Write(payload)
	}))
	defer target.Close()
	p := map[string]any{"node": map[string]any{"type": "socks5", "server": "127.0.0.1", "port": port}, "url": target.URL, "ip_check_url": target.URL + "/ip", "duration_seconds": float64(1), "parallel": float64(1)}
	result = r.Handle(context.Background(), wire.Command{ID: "speed", Action: "speedtest.run", Params: p})
	if result.Status != "success" {
		t.Fatalf("real mihomo measure: %s %+v", result.Error, result.Data)
	}
	if result.Data["download_bytes"].(int64) <= 0 || result.Data["direct_fallback"] != false {
		t.Fatal("missing real proxied download")
	}
	if result.Data["ip"] != "203.0.113.7" || result.Data["exit_ip_verified"] != true {
		t.Fatal("exit IP did not come through the real mihomo proxy")
	}
	p["download_bytes"] = float64(1 << 20)
	p["duration_seconds"] = float64(10)
	for _, parallel := range []int{1, 64} {
		p["parallel"] = float64(parallel)
		bounded := r.Handle(context.Background(), wire.Command{ID: "bounded", Action: "speedtest.run", Params: p})
		if bounded.Status != "success" || bounded.Data["download_bytes"] != int64(1<<20) {
			t.Fatalf("bounded proxy download failed: %+v", bounded)
		}
	}
	p["latency_only"] = true
	beforeDownloads := downloads.Load()
	latency := r.Handle(context.Background(), wire.Command{ID: "latency", Action: "speedtest.run", Params: p})
	if latency.Status != "success" || downloads.Load() != beforeDownloads || latency.Data["download_mbps"] != nil {
		t.Fatalf("latency downloaded payload: %+v", latency)
	}
	delete(p, "latency_only")
	runtime.Close()
	before := requests.Load()
	result = r.Handle(context.Background(), wire.Command{ID: "offline", Action: "speedtest.run", Params: p})
	if result.Status != "failed" {
		t.Fatal("offline proxy returned successful speed")
	}
	if requests.Load() != before {
		t.Fatal("measurement fell back to direct target request")
	}
}

func TestMissingOrUnpinnedBinaryRejected(t *testing.T) {
	if _, e := New(Config{Binary: "missing", Version: "v1", SHA256: "wrong", DataDir: t.TempDir()}); e == nil {
		t.Fatal("unpinned core accepted")
	}
}
