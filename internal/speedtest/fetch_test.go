package speedtest

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSourceFetchLimitsCredentialsAndLocalAccess(t *testing.T) {
	receivedCredentials := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCredentials = r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != ""
		w.Header().Set("subscription-userinfo", "upload=1; download=2; total=3")
		w.Header().Set("Set-Cookie", "secret=private")
		w.Write([]byte("vless://subscription"))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer redirect.Close()
	runner := &Runner{cfg: Config{SourceID: "home-id", SourceMode: "home", SourceAllowPrivate: true}}
	out, e := runner.fetchSource(context.Background(), map[string]any{"url": redirect.URL, "headers": map[string]any{"Authorization": "Bearer private", "Cookie": "session=private"}})
	if e != nil {
		t.Fatal(e)
	}
	if receivedCredentials {
		t.Fatal("credentials crossed redirect origin")
	}
	b, e := base64.StdEncoding.DecodeString(out["body_base64"].(string))
	if e != nil || string(b) != "vless://subscription" {
		t.Fatal("wrong encoded subscription")
	}
	headers := out["headers"].(map[string]string)
	if headers["subscription-userinfo"] == "" || headers["set-cookie"] != "" {
		t.Fatal("source response header whitelist failed")
	}
	runner.cfg.SourceAllowPrivate = false
	if _, e = runner.fetchSource(context.Background(), map[string]any{"url": target.URL}); e == nil {
		t.Fatal("Home fetched private address by default")
	}
	runner.cfg.SourceAllowPrivate = true
	runner.cfg.SourceAllowedOrigins = []string{redirect.URL}
	if _, e = runner.fetchSource(context.Background(), map[string]any{"url": redirect.URL}); e == nil {
		t.Fatal("redirect bypassed origin allowlist")
	}
	runner.cfg.SourceAllowedOrigins = nil
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(bytes.Repeat([]byte{'x'}, (8<<20)+1)) }))
	defer huge.Close()
	if _, e = runner.fetchSource(context.Background(), map[string]any{"url": huge.URL}); e == nil {
		t.Fatal("oversized subscription accepted")
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, e = runner.fetchSource(ctx, map[string]any{"url": target.URL}); e == nil {
		t.Fatal("expired source request ignored cancellation")
	}
}
func TestExitIPParsesOnlyActualIPResponse(t *testing.T) {
	value := `{"ip":"203.0.113.7"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(value)) }))
	defer srv.Close()
	ip, e := proxyExitIP(context.Background(), srv.Client(), srv.URL)
	if e != nil || ip != "203.0.113.7" {
		t.Fatal("actual IP response not parsed")
	}
	value = `{"country":"test"}`
	if _, e = proxyExitIP(context.Background(), srv.Client(), srv.URL); e == nil {
		t.Fatal("non-IP response fabricated exit IP")
	}
}
