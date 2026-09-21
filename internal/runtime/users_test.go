package runtime

import (
	"context"
	"testing"
)

func TestDynamicProtocolAccountsRejectMissingAndUnsupportedCredentials(t *testing.T) {
	for _, v := range []struct {
		kind string
		user map[string]any
		ok   bool
	}{
		{"hysteria", map[string]any{"email": "a", "auth": "secret"}, true},
		{"hysteria", map[string]any{"email": "a", "password": "wrong-field"}, false},
		{"shadowsocks", map[string]any{"email": "a", "method": "aes-128-gcm", "password": "secret"}, true},
		{"shadowsocks", map[string]any{"email": "a", "method": "aes-256-gcm", "password": "secret"}, true},
		{"shadowsocks", map[string]any{"email": "a", "method": "chacha20-ietf-poly1305", "password": "secret"}, true},
		{"shadowsocks", map[string]any{"email": "a", "method": "2022-blake3-aes-128-gcm", "password": "secret"}, false},
		{"shadowsocks", map[string]any{"email": "a", "method": "none", "password": "secret"}, false},
	} {
		u, e := makeUser(v.kind, v.user)
		if (e == nil) != v.ok {
			t.Fatalf("%s credential validation: %v", v.kind, e)
		}
		if e == nil {
			if _, e = u.ToMemoryUser(); e != nil {
				t.Fatal(e)
			}
		}
	}
}

func TestUnlimitedSpliceRegistrationTracksPolicyActivationAndRemoval(t *testing.T) {
	p := newPolicies()
	closed := 0
	release, allowed := p.BeginUnboundedSplice(context.Background(), "email", func() { closed++ })
	if !allowed {
		t.Fatal("unconfigured user did not receive original raw fast path")
	}
	p.apply([]UserPolicy{{UserID: "user", Emails: []string{"email"}, BytesPerSecond: 1000}})
	if closed != 1 {
		t.Fatal("previous unbounded transfer can bypass new policy")
	}
	release()
	release()
	if _, ok := p.BeginUnboundedSplice(context.Background(), "email", func() {}); ok {
		t.Fatal("limited transfer entered unbounded fast path")
	}
	p.apply(nil)
	cleanup, ok := p.BeginUnboundedSplice(context.Background(), "email", func() { closed++ })
	if !ok {
		t.Fatal("policy removal did not restore original fast path")
	}
	p.apply([]UserPolicy{{UserID: "user", Emails: []string{"email"}, IPLimit: 1}})
	if closed != 2 {
		t.Fatal("IP policy transition did not leave unlimited fast path")
	}
	cleanup()
}
