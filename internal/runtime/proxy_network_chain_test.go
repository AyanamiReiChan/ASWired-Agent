package runtime

import (
	"fmt"
	"net"
	"testing"
)

func TestProxyIPv6GuardTransparentFreedomChains(t *testing.T) {
	ipv4, ipv6 := proxyGuardTarget(t, false), proxyGuardTarget(t, true)
	for _, chain := range []string{"proxySettings", "dialerProxy"} {
		for _, redirect := range []struct {
			name, destination string
			allowed           bool
		}{
			{"ipv4", ipv4.Listener.Addr().String(), true},
			{"ipv6", ipv6.Listener.Addr().String(), false},
			{"aaaa-only", net.JoinHostPort("v6.test", fmt.Sprint(ipv6.Listener.Addr().(*net.TCPAddr).Port)), false},
		} {
			t.Run(chain+"/"+redirect.name, func(t *testing.T) {
				r := newTestRuntime(t)
				port := freePort(t)
				cfg := proxyGuardConfig(port)
				first := map[string]any{"tag": "first-direct", "protocol": "freedom"}
				if chain == "proxySettings" {
					first["proxySettings"] = map[string]any{"tag": "redirect-direct"}
				} else {
					first["streamSettings"] = map[string]any{"sockopt": map[string]any{"dialerProxy": "redirect-direct"}}
				}
				cfg["outbounds"] = []any{first, map[string]any{"tag": "redirect-direct", "protocol": "freedom", "settings": map[string]any{"redirect": redirect.destination, "domainStrategy": "UseIP"}}}
				requested := proxyGuardURL("127.0.0.1", ipv4.Listener.Addr().(*net.TCPAddr).Port)
				// Positive control proves the redirect target and transparent chain
				// are reachable, rather than mistaking a broken fixture for blocking.
				command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": false})
				proxyGuardRequest(t, port, requested, true)
				command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": true})
				proxyGuardRequest(t, port, requested, redirect.allowed)
			})
		}
	}
}
