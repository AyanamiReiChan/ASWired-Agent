package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/core"
	"golang.org/x/net/proxy"
	"google.golang.org/protobuf/proto"
)

func TestRoutingFirstMatchAndDefaultOverRealProxy(t *testing.T) {
	r := newTestRuntime(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "routing-ok") }))
	defer target.Close()
	port := freePort(t)
	cfg := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"tag": "entry", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"tag": "block", "protocol": "blackhole"}, map[string]any{"tag": "direct", "protocol": "freedom"}}}
	allow := map[string]any{"type": "field", "inboundTag": []any{"entry"}, "ip": []any{"127.0.0.1"}, "outboundTag": "direct"}
	catchAll := map[string]any{"type": "field", "inboundTag": []any{"entry"}, "outboundTag": "block"}
	request := func(wantSuccess bool) {
		dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), nil, &net.Dialer{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		res, err := client.Get(target.URL)
		if !wantSuccess {
			if err == nil {
				res.Body.Close()
				t.Fatal("blocked request reached target")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if string(body) != "routing-ok" {
			t.Fatalf("wrong payload: %s", body)
		}
	}
	cfg["routing"] = map[string]any{"rules": []any{allow, catchAll}}
	command(t, r, "core.config.apply", map[string]any{"config": cfg})
	request(true)
	cfg["routing"] = map[string]any{"rules": []any{catchAll, allow}}
	command(t, r, "core.config.apply", map[string]any{"config": cfg})
	request(false)
	cfg["routing"] = map[string]any{"rules": []any{}}
	command(t, r, "core.config.apply", map[string]any{"config": cfg})
	request(false)
	cfg["outbounds"] = []any{map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "block", "protocol": "blackhole"}}
	command(t, r, "core.config.apply", map[string]any{"config": cfg})
	request(true)
}

func TestRoutingGeoDownloadsAreVerifiedAndCached(t *testing.T) {
	// macOS exposes its temporary directory through /var -> /private/var.
	// Use the physical test root without weakening managed-path link checks.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_LOCATION_ASSET", dir)
	data, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "OPENAI", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: "openai.com"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	wrong := false
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/geosite.dat.sha256sum" {
			if wrong {
				fmt.Fprintf(w, "%064d  geosite.dat", 0)
			} else {
				fmt.Fprintf(w, "%x  geosite.dat", sha256.Sum256(data))
			}
			return
		}
		w.Write(data)
	}))
	defer server.Close()
	path := filepath.Join(dir, "geosite.dat")
	wrong = true
	if downloadGeoAsset(context.Background(), server.Client(), server.URL+"/", "geosite.dat", path) == nil {
		t.Fatal("wrong hash accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid asset persisted")
	}
	wrong = false
	if err := downloadGeoAsset(context.Background(), server.Client(), server.URL+"/", "geosite.dat", path); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","domain":["geosite:openai"],"outboundTag":"direct"}]}}`)
	before := requests
	if err := ensureGeoAssets(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if requests != before {
		t.Fatal("cached asset re-downloaded")
	}
	if _, err := parseConfig(raw); err != nil {
		t.Fatal(err)
	}
}

func TestRoutingAllBalancerStrategiesParse(t *testing.T) {
	for _, strategy := range []string{"random", "roundRobin", "leastPing", "leastLoad"} {
		t.Run(strategy, func(t *testing.T) {
			cfg := map[string]any{"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "proxy-one"}}, "routing": map[string]any{"rules": []any{map[string]any{"type": "field", "network": "tcp,udp", "balancerTag": "pool"}}, "balancers": []any{map[string]any{"tag": "pool", "selector": []any{"proxy-"}, "strategy": map[string]any{"type": strategy}}}}}
			if strategy == "leastPing" {
				cfg["observatory"] = map[string]any{"subjectSelector": []any{"proxy-"}, "probeURL": "https://www.gstatic.com/generate_204", "probeInterval": "1m", "enableConcurrency": true}
			}
			if strategy == "leastLoad" {
				cfg["burstObservatory"] = map[string]any{"subjectSelector": []any{"proxy-"}, "pingConfig": map[string]any{"destination": "https://www.gstatic.com/generate_204", "interval": "1m", "sampling": 2, "timeout": "10s"}}
			}
			raw, _ := json.Marshal(cfg)
			parsed, err := parseConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := core.New(parsed)
			if err != nil {
				t.Fatal(err)
			}
			instance.Close()
		})
	}
}
