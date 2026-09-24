package runtime

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestProxyNetworkCommandPolicyOverridesSnapshot(t *testing.T) {
	for _, params := range []map[string]any{nil, {"blockProxyIPv6": true}, {"blockProxyIPv6": false}} {
		raw := []byte(`{"aswired":{"blockProxyIPv6":false},"inbounds":[],"outbounds":[{"protocol":"freedom"}]}`)
		out, err := proxyNetworkConfig(raw, params)
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		json.Unmarshal(out, &cfg)
		want := params["blockProxyIPv6"] != false
		if cfg["aswired"].(map[string]any)["blockProxyIPv6"] != want {
			t.Fatalf("wrong policy: %s", out)
		}
	}
	for _, raw := range []string{"null", "[]", "invalid"} {
		if _, err := proxyNetworkConfig([]byte(raw), nil); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	if _, err := proxyNetworkConfig([]byte(`{}`), map[string]any{"blockProxyIPv6": "false"}); err == nil {
		t.Fatal("non-boolean policy accepted")
	}
}

func TestProxyNetworkStartKeepsExistingConfiguration(t *testing.T) {
	r := newTestRuntime(t)
	old := []byte(`{"log":{"loglevel":"none"},"inbounds":[],"outbounds":[{"protocol":"freedom"}]}`)
	if err := atomicWrite(r.cfg.XrayConfig, old, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(r.cfg.XrayConfig)
	if err != nil || string(after) != string(old) {
		t.Fatal("startup unexpectedly migrated existing configuration")
	}
	if !r.Capabilities()["proxy_ipv6_guard"] {
		t.Fatal("missing guard capability")
	}
}

func TestProxyNetworkDisablingRemovesGeneratedGuardOnly(t *testing.T) {
	raw := []byte(`{"aswired":{"blockProxyIPv6":true},"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"aswired-block-ipv6"}],"routing":{"rules":[{"ruleTag":"aswired-block-ipv6","ip":["::/0"],"outboundTag":"aswired-block-ipv6"},{"domain":["full:test"],"outboundTag":"direct"}]}}`)
	out, err := proxyNetworkConfig(raw, map[string]any{"blockProxyIPv6": false})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	json.Unmarshal(out, &cfg)
	if len(cfg["outbounds"].([]any)) != 1 || len(cfg["routing"].(map[string]any)["rules"].([]any)) != 1 {
		t.Fatal("generated guards survived disabling policy or custom rule removed")
	}
}
