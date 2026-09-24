package runtime

import (
	"net"
	"testing"
)

func TestProxyIPv6GuardPreservesDualStackRoutingModes(t *testing.T) {
	target := proxyGuardTarget(t, false)
	for _, strategy := range []string{"IPOnDemand", "IPIfNonMatch"} {
		t.Run(strategy, func(t *testing.T) {
			r := newTestRuntime(t)
			port := freePort(t)
			cfg := proxyGuardConfig(port)
			cfg["outbounds"] = []any{map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "block", "protocol": "blackhole"}}
			rules := []any{map[string]any{"type": "field", "ip": []string{"127.0.0.1/32"}, "outboundTag": "direct"}}
			cfg["routing"] = map[string]any{"domainStrategy": strategy, "rules": append([]any{map[string]any{"type": "field", "inboundTag": []string{"business-entry"}, "ip": []string{"::/0"}, "outboundTag": "block"}}, rules...)}
			// A redundant router IPv6 deny sees the AAAA answer for dual.test,
			// rejecting the whole domain before the destination guard can use A.
			command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": true})
			url := proxyGuardURL("dual.test", target.Listener.Addr().(*net.TCPAddr).Port)
			proxyGuardRequest(t, port, url, false)
			// The controller now retains user routing and sends policy metadata
			// only. The hard guard handles the resulting actual destination.
			cfg["routing"] = map[string]any{"domainStrategy": strategy, "rules": rules}
			command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": true})
			proxyGuardRequest(t, port, url, true)
			proxyGuardRequest(t, port, proxyGuardURL("::1", target.Listener.Addr().(*net.TCPAddr).Port), false)
		})
	}
}
