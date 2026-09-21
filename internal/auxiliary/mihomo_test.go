package auxiliary

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuxiliaryConfigurationOnlyPermitsLocalAccountedBridges(t *testing.T) {
	m, e := New(Config{DataDir: t.TempDir()})
	if e != nil {
		t.Fatal(e)
	}
	listener := Listener{Name: "snell-test", Type: "snell", Listen: "127.0.0.1", Port: 20000, Version: 4, Users: []User{{Email: "instance-1", Password: "psk", Bridge: Bridge{Port: 20001, ID: "11111111-1111-4111-8111-111111111111"}}}}
	if e = m.validate([]Listener{listener}); e != nil {
		t.Fatal(e)
	}
	b, e := m.configuration([]Listener{listener}, "127.0.0.1:20002", "test-secret")
	if e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	if e = json.Unmarshal(b, &cfg); e != nil {
		t.Fatal(e)
	}
	if cfg["external-controller"] != "127.0.0.1:20002" || cfg["secret"] != "test-secret" || !strings.Contains(string(b), "MATCH,REJECT") {
		t.Fatal("unsafe local API or direct fallback")
	}
	for _, mutate := range []func(*Listener){func(l *Listener) { l.Users = append(l.Users, l.Users[0]) }, func(l *Listener) { l.Version = 5 }, func(l *Listener) { l.UDP = true }, func(l *Listener) { l.Listen = "hostname" }, func(l *Listener) { l.Users[0].Email = "foo,DIRECT" }, func(l *Listener) { l.Users[0].Bridge.ID = "not-a-uuid" }} {
		copy := listener
		copy.Users = append([]User(nil), listener.Users...)
		mutate(&copy)
		if m.validate([]Listener{copy}) == nil {
			t.Fatal("unsafe or unsupported candidate accepted")
		}
	}
	if m.Available() {
		t.Fatal("missing binary reported available")
	}
	m.desired = state{Enabled: true, Listeners: []Listener{listener}}
	summary, _ := json.Marshal(m.Snapshot())
	if strings.Contains(string(summary), "psk") || strings.Contains(string(summary), "11111111") {
		t.Fatal("snapshot exposed user credentials")
	}
}

func TestAuxiliaryLocalAPIAlwaysSendsAuthentication(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Header.Get("Authorization") != "Bearer dedicated-private-secret" {
			t.Error("missing private API credential")
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	m := &Manager{api: strings.TrimPrefix(server.URL, "http://"), secret: "dedicated-private-secret"}
	if e := m.apiRequest(context.Background(), "/version"); e != nil || !called {
		t.Fatal("actual API validation did not execute")
	}
}

func TestEmptyPublicationForgetsAuxiliaryListenersWithoutBinary(t *testing.T) {
	root := t.TempDir()
	m, err := New(Config{DataDir: root})
	if err != nil {
		t.Fatal(err)
	}
	m.desired = state{Enabled: true, Listeners: []Listener{{Name: "deleted", Type: "snell", Port: 12345}}}
	if _, err = m.Apply(context.Background(), []any{}); err != nil {
		t.Fatal(err)
	}
	restored, err := New(Config{DataDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if restored.desired.Enabled || len(restored.desired.Listeners) != 0 {
		t.Fatal("removed listener can be restored")
	}
}
