package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
)

func TestFirewallDirectorySyncFailurePreservesRecovery(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			r, fake, port := newFirewallRuntime(t)
			syncs := 0
			r.firewallSyncDir = func(dir string) error {
				if dir != r.cfg.DataDir {
					t.Fatalf("synced wrong directory: %s", dir)
				}
				syncs++
				if syncs == 1 && fake.applies != 0 {
					t.Fatal("changed kernel before durable intent")
				}
				if syncs == failAt {
					return errors.New("injected directory sync failure")
				}
				return nil
			}
			result := r.Handle(context.Background(), wire.Command{ID: "sync-failure", Action: "network.firewall.apply", Params: firewallTestParams(port, 1, "192.0.2.1")})
			if result.Status != "failed" || result.Data["applied"] != false || r.firewallReady || r.instance != nil {
				t.Fatalf("persistence failure did not fail closed: %#v", result)
			}
			if _, err := os.Stat(r.firewallPath("firewall-pending.json")); err != nil {
				t.Fatalf("lost recovery journal: %v", err)
			}
			if failAt == 1 && fake.applies != 0 {
				t.Fatal("nondurable intent changed kernel")
			}
			r.firewallSyncDir = nil
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !r.firewallReady || r.instance == nil {
				t.Fatal("durable journal could not recover listeners")
			}
			if _, err := os.Stat(r.firewallPath("firewall-pending.json")); !os.IsNotExist(err) {
				t.Fatal("recovery did not remove journal")
			}
		})
	}
}

func TestFirewallManagementPortChangesAreSerialized(t *testing.T) {
	r, _, port := newFirewallRuntime(t)
	bootPort := managementPort(r.cfg.ListenAddress)
	entered, release, updated := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		updated <- r.UpdateConnection("http", "0.0.0.0:"+strconv.Itoa(port), func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	result := make(chan wire.Result, 1)
	go func() {
		result <- r.Handle(context.Background(), wire.Command{ID: "concurrent", Action: "network.firewall.apply", Params: firewallTestParams(port, 1, "192.0.2.1")})
	}()
	select {
	case got := <-result:
		close(release)
		t.Fatalf("firewall bypassed management persistence lock: %#v", got)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	if got := <-result; got.Status != "failed" {
		t.Fatalf("new management port accepted as firewall target: %#v", got)
	}
	if !r.managementPorts[bootPort] || !r.managementPorts[port] {
		t.Fatal("old or current management port was not reserved")
	}
	if err := r.UpdateConnection("pull", "0.0.0.0:23890", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(firewallTestConfig(port, "0.0.0.0"))
	if len(r.firewallTargets(raw)) != 0 {
		t.Fatal("recent management port became available before old listener closed")
	}
}

func TestFirewallProtectedPortRejectsManagementUpdate(t *testing.T) {
	r, _, port := newFirewallRuntime(t)
	command(t, r, "network.firewall.apply", firewallTestParams(port, 1, "192.0.2.1"))
	before := r.cfg
	called := false
	err := r.UpdateConnection("http", "[::]:"+strconv.Itoa(port), func() error { called = true; return nil })
	if err == nil || called || !reflect.DeepEqual(r.cfg, before) {
		t.Fatal("protected management change persisted")
	}
	if err = r.UpdateConnection("http", "0.0.0.0:23890", func() error { return errors.New("disk full") }); err == nil || !reflect.DeepEqual(r.cfg, before) {
		t.Fatal("failed persistence changed runtime settings")
	}
	state, err := r.readFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	state.Revision++
	state.Rules, state.Bindings = []FirewallRule{}, []FirewallTarget{}
	if err = r.saveFirewallFile("firewall-pending.json", state); err != nil {
		t.Fatal(err)
	}
	if err = r.UpdateConnection("http", "0.0.0.0:"+strconv.Itoa(port), func() error { called = true; return nil }); err == nil || called {
		t.Fatal("pending removal prematurely released management port")
	}
}

func TestFirewallWildcardIPv6Canonicalized(t *testing.T) {
	r := newTestRuntime(t)
	raw, _ := json.Marshal(firewallTestConfig(14443, "0:0:0:0:0:0:0:0"))
	targets := r.firewallTargets(raw)
	if len(targets) != 1 || targets[0].Listen != "::" {
		t.Fatalf("IPv6 wildcard not canonical: %#v", targets)
	}
}
