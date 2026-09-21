package runtime

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedVlessTransferUsesSharedPolicyHook(t *testing.T) {
	r := newTestRuntime(t)
	payload := bytes.Repeat([]byte("x"), 128<<10)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(payload) }))
	defer target.Close()
	port := freePort(t)
	id := "11111111-1111-4111-8111-111111111111"
	cfg := map[string]any{"log": map[string]any{"loglevel": "none"}, "stats": map[string]any{}, "policy": map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}}}, "inbounds": []any{map[string]any{"tag": "vless", "listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"email": "instance-a", "id": id}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
	command(t, r, "core.config.apply", map[string]any{"config": cfg})
	command(t, r, "core.policy.apply", map[string]any{"policies": []any{map[string]any{"user_id": "u", "emails": []any{"instance-a"}, "bytes_per_second": 131072, "connection_limit": 1, "direction": "download"}}})
	conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, rawPort, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	targetPort, _ := strconv.Atoi(rawPort)
	uuid, _ := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	header := append([]byte{0}, uuid...)
	header = append(header, 0, 1)
	header = binary.BigEndian.AppendUint16(header, uint16(targetPort))
	header = append(header, 1, 127, 0, 0, 1)
	header = append(header, []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")...)
	start := time.Now()
	if _, e = conn.Write(header); e != nil {
		t.Fatal(e)
	}
	var responseHeader [2]byte
	if _, e = io.ReadFull(conn, responseHeader[:]); e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(conn)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(body, payload) {
		t.Fatalf("VLESS response missing payload (%d bytes)", len(body))
	}
	if elapsed := time.Since(start); elapsed < 350*time.Millisecond {
		t.Fatalf("authenticated traffic bypassed rate hook: %s", elapsed)
	}
	stats := command(t, r, "core.stats", nil)
	if stats.Data["counters"].(map[string]int64)["user>>>instance-a>>>traffic>>>downlink"] < int64(len(payload)) {
		t.Fatal("user byte counters missing actual traffic")
	}
	conn.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.policies.mu.Lock()
		count := r.policies.state("instance-a").connections
		r.policies.mu.Unlock()
		if count == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("closed authenticated session leaked connection count")
}

func TestCoreGenerationSurvivesAgentRestart(t *testing.T) {
	r := newTestRuntime(t)
	if e := r.advanceGeneration(); e != nil {
		t.Fatal(e)
	}
	first := r.generation
	r.Close()
	next, e := New(r.cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if e = next.advanceGeneration(); e != nil {
		t.Fatal(e)
	}
	if next.generation <= first {
		t.Fatal("core generation reused after Agent restart")
	}
}
