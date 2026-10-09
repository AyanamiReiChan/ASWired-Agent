package runtime

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Captured from nft 1.0.2/1.0.9 on the Ubuntu 22.04/24.04 isolated-network CI
// jobs. Both remove redundant meta selectors and print /32 and /128 as plain
// addresses; 1.0.2 also drops the table comment. The ownership chain was added
// after these captures, so the raw fixtures must fail ownership validation.
func TestFirewallKernelJSONFormat(t *testing.T) {
	for version, ports := range map[string][]int{"1.0.2": {43519, 44411}, "1.0.9": {40543, 46371}} {
		t.Run(version, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/firewall-nft-" + version + ".json")
			if err != nil {
				t.Fatal(err)
			}
			r := newTestRuntime(t)
			r.hostExec = func(_ context.Context, binary string, args ...string) (string, error) {
				if binary != "nft" || (strings.Join(args, " ") != "-j list tables inet" && strings.Join(args, " ") != "-j list table inet "+firewallTable) {
					t.Fatal("unexpected command", binary, args)
				}
				return string(raw), nil
			}
			state := &firewallState{Owner: strings.Repeat("0", 64), Rules: []FirewallRule{
				{Protocol: "tcp", Port: ports[0], AllowedCIDRs: []string{"192.0.2.10/32", "2001:db8::10/128"}},
				{Protocol: "tcp", Port: ports[1], AllowedCIDRs: []string{"192.0.2.10/32", "2001:db8::10/128"}},
			}}
			observed, err := r.observeFirewall(context.Background())
			if err != nil || observed.Owner != "" || observed.Valid || r.checkFirewallOwnership(observed, state) == nil {
				t.Fatalf("comment-only or unmarked ownership accepted: %#v / %v", observed, err)
			}
			var listing map[string][]map[string]any
			if err = json.Unmarshal(raw, &listing); err != nil {
				t.Fatal(err)
			}
			marker := map[string]any{"chain": map[string]any{"family": "inet", "table": firewallTable, "name": "owner_" + state.Owner, "handle": 10}}
			listing["nftables"] = append(listing["nftables"], marker)
			raw, _ = json.Marshal(listing)
			observed, err = r.observeFirewall(context.Background())
			if err != nil || !firewallMatches(observed, state) {
				t.Fatalf("real kernel rules with ownership chain were not equivalent: %#v / %v", observed, err)
			}
			// Reading canonical formatting must not weaken the complete policy check.
			missingDrop := observed
			missingDrop.Atoms = append([]firewallAtom{}, observed.Atoms[:len(observed.Atoms)-1]...)
			if firewallMatches(missingDrop, state) {
				t.Fatal("missing final deny accepted")
			}
			reordered := observed
			reordered.Atoms = append([]firewallAtom{}, observed.Atoms...)
			reordered.Atoms[0], reordered.Atoms[2] = reordered.Atoms[2], reordered.Atoms[0]
			if firewallMatches(reordered, state) {
				t.Fatal("reordered verdict rules accepted")
			}
			jsonMap(marker["chain"])["hook"] = "output"
			raw, _ = json.Marshal(listing)
			observed, err = r.observeFirewall(context.Background())
			if err != nil || observed.Owner != "" || observed.Valid || r.checkFirewallOwnership(observed, state) == nil {
				t.Fatal("nonempty marker shape accepted as ownership")
			}
			delete(jsonMap(marker["chain"]), "hook")
			listing["nftables"] = append(listing["nftables"], map[string]any{"rule": map[string]any{"family": "inet", "table": firewallTable, "chain": "owner_" + state.Owner, "expr": []any{map[string]any{"accept": nil}}}})
			raw, _ = json.Marshal(listing)
			observed, err = r.observeFirewall(context.Background())
			if err != nil || observed.Owner != "" || observed.Valid || r.checkFirewallOwnership(observed, state) == nil {
				t.Fatal("marker containing packet rules accepted as ownership")
			}
			listing["nftables"] = listing["nftables"][:len(listing["nftables"])-1]
			jsonMap(marker["chain"])["name"] = "owner_" + strings.Repeat("1", 64)
			raw, _ = json.Marshal(listing)
			observed, err = r.observeFirewall(context.Background())
			if err != nil || r.checkFirewallOwnership(observed, state) == nil {
				t.Fatal("foreign installation token accepted")
			}
		})
	}
}

func TestFirewallNamedPayloadSelectors(t *testing.T) {
	port := firewallMatch(firewallPayload("tcp", "dport"), 14443)
	source := firewallMatch(firewallPayload("ip", "saddr"), "192.0.2.10")
	protocol := firewallMatch(firewallMeta("l4proto"), "tcp")
	family := firewallMatch(firewallMeta("nfproto"), "ipv4")
	accept, drop := map[string]any{"accept": nil}, map[string]any{"drop": nil}
	parse := func(expressions []any) (firewallAtom, error) {
		raw, err := json.Marshal(expressions)
		if err != nil {
			t.Fatal(err)
		}
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		return parseFirewallAtom(decoded)
	}
	for _, expressions := range [][]any{
		{port, source, accept},
		{source, port, accept},
		{family, protocol, port, source, accept},
		{source, port, protocol, family, accept},
		{port, family, source, protocol, accept},
	} {
		atom, err := parse(expressions)
		if err != nil || !reflect.DeepEqual(atom, firewallAtom{Protocol: "tcp", Port: 14443, CIDR: "192.0.2.10/32", Verdict: "accept"}) {
			t.Fatalf("equivalent selectors rejected: %#v / %v", atom, err)
		}
	}
	if atom, err := parse([]any{port, drop}); err != nil || atom != (firewallAtom{Protocol: "tcp", Port: 14443, Verdict: "drop"}) {
		t.Fatalf("implicit-protocol deny rejected: %#v / %v", atom, err)
	}
	bad := map[string][]any{
		"contradictory protocol before": {firewallMatch(firewallMeta("l4proto"), "udp"), port, source, accept},
		"contradictory protocol after":  {port, source, firewallMatch(firewallMeta("l4proto"), "udp"), accept},
		"contradictory family before":   {firewallMatch(firewallMeta("nfproto"), "ipv6"), port, source, accept},
		"contradictory family after":    {port, source, firewallMatch(firewallMeta("nfproto"), "ipv6"), accept},
		"duplicate protocol":            {protocol, protocol, port, source, accept},
		"duplicate family":              {family, port, source, family, accept},
		"duplicate port":                {port, port, source, accept},
		"duplicate source":              {port, source, source, accept},
		"raw payload":                   {firewallMatch(map[string]any{"payload": map[string]any{"base": "th", "offset": 16, "len": 16}}, 14443), source, accept},
		"generic transport payload":     {firewallMatch(firewallPayload("th", "dport"), 14443), source, accept},
		"wrong source family":           {port, firewallMatch(firewallPayload("ip6", "saddr"), "192.0.2.10"), accept},
		"unrestricted accept":           {port, accept},
		"family-specific deny":          {family, port, drop},
		"source-specific deny":          {port, source, drop},
		"premature verdict":             {port, accept, source},
		"unknown statement":             {port, source, map[string]any{"counter": nil}, accept},
		"source object extra data":      {port, firewallMatch(firewallPayload("ip", "saddr"), map[string]any{"prefix": map[string]any{"addr": "192.0.2.0", "len": 24}, "extra": true}), accept},
	}
	for name, expressions := range bad {
		t.Run(name, func(t *testing.T) {
			if atom, err := parse(expressions); err == nil {
				t.Fatalf("invalid condition accepted: %#v", atom)
			}
		})
	}
}
