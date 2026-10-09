package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
)

type fakeFirewall struct {
	t          *testing.T
	objects    []map[string]any
	calls      int
	applies    int
	checks     int
	failCheck  bool
	failApply  bool
	afterApply func()
	readError  error
}

func (f *fakeFirewall) execute(_ context.Context, binary string, args ...string) (string, error) {
	f.t.Helper()
	f.calls++
	if binary != "nft" {
		f.t.Fatalf("unexpected host command %s", binary)
	}
	jsonText := func(value any) string {
		b, e := json.Marshal(value)
		if e != nil {
			f.t.Fatal(e)
		}
		return string(b)
	}
	if strings.Join(args, " ") == "-j list tables inet" {
		if f.readError != nil {
			return "", f.readError
		}
		tables := []map[string]any{}
		for _, o := range f.objects {
			if o["table"] != nil {
				tables = append(tables, o)
			}
		}
		return jsonText(map[string]any{"nftables": tables}), nil
	}
	if strings.Join(args, " ") == "-j list table inet "+firewallTable {
		return jsonText(map[string]any{"nftables": f.objects}), nil
	}
	check := len(args) > 0 && args[0] == "-c"
	if check {
		f.checks++
		args = args[1:]
	}
	if len(args) != 3 || args[0] != "-j" || args[1] != "-f" {
		f.t.Fatalf("unsafe or unexpected nft invocation: %v", args)
	}
	b, e := os.ReadFile(args[2])
	if e != nil {
		return "", e
	}
	var batch struct {
		NFTables []map[string]map[string]map[string]any `json:"nftables"`
	}
	if e = json.Unmarshal(b, &batch); e != nil {
		f.t.Fatal(e)
	}
	for _, entry := range batch.NFTables {
		for verb, object := range entry {
			for kind, value := range object {
				if value["family"] != "inet" {
					f.t.Fatal("non-inet command")
				}
				if kind == "table" {
					if value["name"] != firewallTable {
						f.t.Fatal("touched foreign table")
					}
				} else if value["table"] != firewallTable {
					f.t.Fatal("touched foreign table object")
				}
				if verb != "delete" && verb != "create" && verb != "add" {
					f.t.Fatal("unrestricted nft command")
				}
			}
		}
	}
	if check {
		if f.failCheck {
			return "", errors.New("injected nft check failure")
		}
		return "", nil
	}
	f.applies++
	if f.failApply {
		f.failApply = false
		return "", errors.New("injected atomic nft apply failure")
	}
	objects := append([]map[string]any{}, f.objects...)
	for _, entry := range batch.NFTables {
		for verb, object := range entry {
			if verb == "delete" {
				objects = []map[string]any{}
				continue
			}
			for kind, value := range object {
				objects = append(objects, map[string]any{kind: value})
			}
		}
	}
	f.objects = objects
	if f.afterApply != nil {
		hook := f.afterApply
		f.afterApply = nil
		hook()
	}
	return "", nil
}
func firewallTestConfig(port int, listen string) map[string]any {
	return map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"tag": "customer-vless", "listen": listen, "port": port, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": "82d5832b-ef17-4e7d-9512-39fbdcb247b3", "email": "firewall-test"}}}, "streamSettings": map[string]any{"network": "tcp", "security": "none"}}}, "outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}}}
}
func firewallTestParams(port int, revision int, allowed ...string) map[string]any {
	return map[string]any{"revision": revision, "rules": []FirewallRule{{ID: "customer", Name: "客户入口", Protocol: "tcp", Port: port, AllowedCIDRs: allowed}}}
}
func newFirewallRuntime(t *testing.T) (*Runtime, *fakeFirewall, int) {
	t.Helper()
	r := newTestRuntime(t)
	fake := &fakeFirewall{t: t, objects: []map[string]any{}}
	r.hostExec = fake.execute
	port := freePort(t)
	command(t, r, "core.config.apply", map[string]any{"config": firewallTestConfig(port, "0.0.0.0")})
	if fake.calls != 0 {
		t.Fatal("unconfigured startup ran nft")
	}
	return r, fake, port
}

func TestFirewallRequestValidation(t *testing.T) {
	good := firewallTestParams(14443, 1, "192.0.2.18", "2001:db8::18", "192.0.2.129/24", "192.0.2.0/24")
	req, e := decodeFirewall(good)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(req.Rules[0].AllowedCIDRs, []string{"192.0.2.0/24", "192.0.2.18/32", "2001:db8::18/128"}) {
		t.Fatal(req)
	}
	for _, cidr := range []string{"", "0.0.0.0/0", "::/0", "127.0.0.1", "::1", "224.0.0.1", "ff02::1", "0.0.0.0", "::", "::ffff:192.0.2.1", "::ffff:192.0.2.1/128", "fe80::1%eth0", "192.0.2.1; flush ruleset", "192.0.2.1/33"} {
		if _, e = decodeFirewall(firewallTestParams(14443, 1, cidr)); e == nil {
			t.Errorf("accepted invalid CIDR %q", cidr)
		}
	}
	for _, rev := range []any{0, -1, 1.5, 9007199254740992.0, "2"} {
		p := firewallTestParams(14443, 1, "192.0.2.1")
		p["revision"] = rev
		if _, e = decodeFirewall(p); e == nil {
			t.Errorf("accepted invalid revision %v", rev)
		}
	}
	for _, id := range []string{"../escape", "a.b", "_first", strings.Repeat("x", 65)} {
		p := firewallTestParams(14443, 1, "192.0.2.1")
		p["rules"].([]FirewallRule)[0].ID = id
		if _, e = decodeFirewall(p); e == nil {
			t.Errorf("accepted id %s", id)
		}
	}
	p := firewallTestParams(14443, 1, "192.0.2.1")
	p["rules"] = append(p["rules"].([]FirewallRule), FirewallRule{ID: "other", Protocol: "tcp", Port: 14443, AllowedCIDRs: []string{"192.0.2.2"}})
	if _, e = decodeFirewall(p); e == nil {
		t.Fatal("accepted duplicate protocol+port")
	}
	if _, e = decodeFirewall(map[string]any{"revision": 1, "rules": []any{}}); e != nil {
		t.Fatal(e)
	}
	if _, e = decodeFirewall(map[string]any{"revision": 1}); e == nil {
		t.Fatal("missing rules can disable firewall")
	}
}
func TestFirewallApplyLiveVerificationRevisionAndRemoval(t *testing.T) {
	r, fake, port := newFirewallRuntime(t)
	params := firewallTestParams(port, 1, "192.0.2.18", "2001:db8::18")
	result := command(t, r, "network.firewall.apply", params)
	if result.Data["applied"] != true || result.Data["revision"] != uint64(1) || fake.checks != 1 || fake.applies != 1 {
		t.Fatal(result, fake)
	}
	before, e := os.ReadFile(r.firewallPath("firewall.json"))
	if e != nil {
		t.Fatal(e)
	}
	command(t, r, "network.firewall.apply", params)
	if fake.applies != 1 {
		t.Fatal("same revision changed kernel")
	}
	if _, e = os.Stat(r.firewallPath("firewall-pending.json")); !os.IsNotExist(e) {
		t.Fatal("successful apply retained journal")
	}
	conflict := r.Handle(context.Background(), wire.Command{Action: "network.firewall.apply", Params: firewallTestParams(port, 1, "192.0.2.19")})
	if conflict.Status != "failed" {
		t.Fatal("conflicting replay accepted")
	}
	// Keep the ownership comment and alter a rule: status must inspect expressions.
	for _, entry := range fake.objects {
		if rule := jsonMap(entry["rule"]); rule != nil {
			expr := rule["expr"].([]any)
			expr[len(expr)-1] = map[string]any{"drop": nil}
			break
		}
	}
	status := command(t, r, "network.firewall.status", nil)
	if status.Data["applied"] != false {
		t.Fatal("live expression drift was hidden")
	}
	command(t, r, "network.firewall.apply", params)
	if fake.applies != 2 {
		t.Fatal("same revision did not repair drift")
	}
	if after, _ := os.ReadFile(r.firewallPath("firewall.json")); !reflect.DeepEqual(before, after) {
		t.Fatal("same policy changed persisted identity")
	}
	command(t, r, "network.firewall.apply", map[string]any{"revision": 2, "rules": []any{}})
	if len(fake.objects) != 0 {
		t.Fatal("removal kept owned table")
	}
	if replay := r.Handle(context.Background(), wire.Command{Action: "network.firewall.apply", Params: params}); replay.Status != "failed" {
		t.Fatal("old task resurrected removed policy")
	}
	state, e := r.readFirewallState()
	if e != nil || state.Revision != 2 || len(state.Rules) != 0 {
		t.Fatal("removal lost revision tombstone", state, e)
	}
}
func TestFirewallAtomicFailureKeepsLastGoodAndForeignTables(t *testing.T) {
	r, fake, port := newFirewallRuntime(t)
	params := firewallTestParams(port, 1, "192.0.2.18")
	command(t, r, "network.firewall.apply", params)
	old, _ := r.readFirewallState()
	before, _ := os.ReadFile(r.firewallPath("firewall.json"))
	fake.failCheck = true
	if v := r.Handle(context.Background(), wire.Command{Action: "network.firewall.apply", Params: firewallTestParams(port, 2, "192.0.2.19")}); v.Status != "failed" {
		t.Fatal(v)
	}
	fake.failCheck = false
	if fake.applies != 1 {
		t.Fatal("validation failure changed kernel")
	}
	fake.failApply = true
	if v := r.Handle(context.Background(), wire.Command{Action: "network.firewall.apply", Params: firewallTestParams(port, 2, "192.0.2.19")}); v.Status != "failed" {
		t.Fatal(v)
	}
	actual, e := r.observeFirewall(context.Background())
	if e != nil || !firewallMatches(actual, old) {
		t.Fatal("failed transaction did not retain last-good policy", e)
	}
	after, _ := os.ReadFile(r.firewallPath("firewall.json"))
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failure replaced saved policy")
	}
	if _, e = os.Stat(r.firewallPath("firewall-pending.json")); !os.IsNotExist(e) {
		t.Fatal("failure retained candidate journal")
	}
	for _, entry := range fake.objects {
		if table := jsonMap(entry["table"]); table != nil {
			table["comment"] = "owned by administrator"
		}
	}
	applies := fake.applies
	if v := r.Handle(context.Background(), wire.Command{Action: "network.firewall.apply", Params: firewallTestParams(port, 2, "192.0.2.19")}); v.Status != "failed" {
		t.Fatal("foreign table overwritten")
	}
	if fake.applies != applies {
		t.Fatal("mutated foreign table")
	}
}
func TestFirewallJournalRecoveryAndFailClosedStartup(t *testing.T) {
	r, fake, port := newFirewallRuntime(t)
	command(t, r, "network.firewall.apply", firewallTestParams(port, 1, "192.0.2.18"))
	state, e := r.readFirewallState()
	if e != nil {
		t.Fatal(e)
	}
	state.Revision = 2
	state.Rules[0].AllowedCIDRs = []string{"192.0.2.19/32"}
	if e = r.saveFirewallFile("firewall-pending.json", state); e != nil {
		t.Fatal(e)
	}
	r.Close()
	r2, e := New(r.cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r2.Close() })
	r2.hostExec = fake.execute
	fake.objects = nil
	fake.failCheck = true
	if e = r2.Start(context.Background()); e == nil {
		t.Fatal("startup accepted missing firewall")
	}
	if r2.instance != nil {
		t.Fatal("core started before firewall restoration")
	}
	for _, action := range []string{"core.start", "core.restart", "core.config.apply", "mihomo.start", "network.forward.apply"} {
		v := r2.Handle(context.Background(), wire.Command{Action: action, Params: map[string]any{"config": firewallTestConfig(port, "0.0.0.0"), "rules": []any{}}})
		if v.Status != "failed" || !strings.Contains(v.Error, "firewall") {
			t.Fatalf("%s bypassed failure: %+v", action, v)
		}
	}
	fake.failCheck = false
	if e = r2.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	if r2.instance == nil {
		t.Fatal("core not started after restoration")
	}
	actual, e := r2.observeFirewall(context.Background())
	if e != nil || !firewallMatches(actual, state) {
		t.Fatal("pending intent was not restored", e)
	}
	if saved, e := r2.readFirewallFile("firewall.json"); e != nil || saved.Revision != 2 {
		t.Fatal(saved, e)
	}
	if _, e = os.Stat(r2.firewallPath("firewall-pending.json")); !os.IsNotExist(e) {
		t.Fatal("recovery did not finish journal")
	}
}
func TestFirewallProtectedBindingAndManagementPortValidation(t *testing.T) {
	r, _, port := newFirewallRuntime(t)
	command(t, r, "network.firewall.apply", firewallTestParams(port, 1, "192.0.2.18"))
	for _, cfg := range []map[string]any{firewallTestConfig(port, "127.0.0.1"), firewallTestConfig(port+1, "0.0.0.0"), firewallTestConfig(port, "::")} {
		v := r.Handle(context.Background(), wire.Command{Action: "core.config.apply", Params: map[string]any{"config": cfg}})
		if v.Status != "failed" || !strings.Contains(v.Error, "firewall") {
			t.Fatal("changed protected binding", v)
		}
	}
	for _, listen := range []string{"127.0.0.1", "192.0.2.1"} {
		raw, _ := json.Marshal(firewallTestConfig(port, listen))
		if len(r.firewallTargets(raw)) != 0 {
			t.Fatal("exposed non-wildcard listener")
		}
	}
	for _, blocked := range []int{22, 23889} {
		raw, _ := json.Marshal(firewallTestConfig(blocked, "0.0.0.0"))
		if len(r.firewallTargets(raw)) != 0 {
			t.Fatal("exposed management port")
		}
	}
	r.cfg.ListenAddress = "[::]:24444"
	raw, _ := json.Marshal(firewallTestConfig(24444, "::"))
	if len(r.firewallTargets(raw)) != 0 {
		t.Fatal("exposed custom management port")
	}
	command(t, r, "network.firewall.apply", map[string]any{"revision": 2, "rules": []any{}})
	if e := os.Remove(r.cfg.XrayConfig); e != nil {
		t.Fatal(e)
	}
	command(t, r, "network.firewall.apply", map[string]any{"revision": 3, "rules": []any{}})
}
func TestFirewallStatePersistenceFailureRollsBackKernel(t *testing.T) {
	r, fake, port := newFirewallRuntime(t)
	fake.afterApply = func() {
		if e := os.Mkdir(r.firewallPath("firewall.json"), 0700); e != nil {
			t.Fatal(e)
		}
	}
	v := r.Handle(context.Background(), wire.Command{Action: "network.firewall.apply", Params: firewallTestParams(port, 1, "192.0.2.18")})
	if v.Status != "failed" || v.Data["applied"] != false || len(fake.objects) != 0 {
		t.Fatalf("disk failure falsely applied or left new policy: %+v", v)
	}
	if _, e := os.Stat(filepath.Join(r.cfg.DataDir, "firewall-pending.json")); !os.IsNotExist(e) {
		t.Fatal("rollback retained candidate")
	}
}

func TestFirewallUnverifiableRemovalStopsExistingProxy(t *testing.T) {
	r, fake, port := newFirewallRuntime(t)
	command(t, r, "network.firewall.apply", firewallTestParams(port, 1, "192.0.2.18"))
	fake.afterApply = func() { fake.readError = errors.New("kernel observation unavailable after removal") }
	v := r.Handle(context.Background(), wire.Command{Action: "network.firewall.apply", Params: map[string]any{"revision": 2, "rules": []any{}}})
	if v.Status != "failed" || v.Data["applied"] != false || r.instance != nil || r.firewallReady {
		t.Fatalf("unverifiable removal left proxy active: %+v running=%v ready=%v", v, r.instance != nil, r.firewallReady)
	}
	if len(fake.objects) != 0 {
		t.Fatal("fixture did not remove the live table")
	}
	if v = r.Handle(context.Background(), wire.Command{Action: "core.start"}); v.Status != "failed" || r.instance != nil {
		t.Fatal("listener startup bypassed uncertain recovery", v)
	}
	fake.readError = nil
	if e := r.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	if r.instance == nil {
		t.Fatal("verified pending removal did not unblock recovery")
	}
}
