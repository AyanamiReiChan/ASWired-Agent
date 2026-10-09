package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const firewallTable = "aswired_allowlist"

var firewallIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

type FirewallRule struct {
	ID           string   `json:"id"`
	Name         string   `json:"name,omitempty"`
	Protocol     string   `json:"protocol"`
	Port         int      `json:"port"`
	AllowedCIDRs []string `json:"allowedCidrs"`
}
type firewallRequest struct {
	Revision uint64         `json:"revision"`
	Rules    []FirewallRule `json:"rules"`
}
type FirewallTarget struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Listen   string `json:"listen"`
	Kind     string `json:"kind"`
}
type firewallState struct {
	Version  int              `json:"version"`
	Owner    string           `json:"owner"`
	Revision uint64           `json:"revision"`
	Rules    []FirewallRule   `json:"rules"`
	Bindings []FirewallTarget `json:"bindings"`
}
type firewallAtom struct {
	Protocol string
	Port     int
	CIDR     string
	Verdict  string
}
type firewallObserved struct {
	Exists bool
	Owner  string
	Atoms  []firewallAtom
	Valid  bool
}

func decodeFirewall(raw map[string]any) (firewallRequest, error) {
	b, e := json.Marshal(raw)
	if e != nil {
		return firewallRequest{}, e
	}
	var req firewallRequest
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&req); e != nil {
		return req, fmt.Errorf("invalid firewall request: %w", e)
	}
	if req.Revision == 0 || req.Revision > 9007199254740991 || req.Rules == nil || len(req.Rules) > 64 {
		return req, errors.New("firewall requires a positive safe-integer revision and 0..64 explicit rules")
	}
	ids, ports := map[string]bool{}, map[string]bool{}
	for i := range req.Rules {
		r := &req.Rules[i]
		if !firewallIDPattern.MatchString(r.ID) || ids[r.ID] {
			return req, errors.New("firewall rule IDs must be unique safe names of 1..64 characters")
		}
		ids[r.ID] = true
		r.Name = strings.TrimSpace(r.Name)
		if utf8.RuneCountInString(r.Name) > 100 {
			return req, errors.New("firewall rule name exceeds 100 characters")
		}
		if (r.Protocol != "tcp" && r.Protocol != "udp") || r.Port < 1 || r.Port > 65535 {
			return req, errors.New("firewall requires tcp/udp and a port from 1..65535")
		}
		key := firewallPort(r.Protocol, r.Port)
		if ports[key] {
			return req, errors.New("firewall rules cannot share a protocol and port")
		}
		ports[key] = true
		if len(r.AllowedCIDRs) == 0 || len(r.AllowedCIDRs) > 128 {
			return req, errors.New("each firewall rule requires 1..128 allowed IPs or CIDRs; remove a rule to disable its restriction")
		}
		seen := map[string]bool{}
		cidrs := []string{}
		for _, value := range r.AllowedCIDRs {
			prefix, e := firewallPrefix(value)
			if e != nil {
				return req, e
			}
			if !seen[prefix] {
				seen[prefix] = true
				cidrs = append(cidrs, prefix)
			}
		}
		sort.Strings(cidrs)
		r.AllowedCIDRs = cidrs
	}
	sort.Slice(req.Rules, func(i, j int) bool {
		a, b := req.Rules[i], req.Rules[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Port < b.Port
	})
	return req, nil
}
func firewallPrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	p, e := netip.ParsePrefix(value)
	if e != nil {
		if a, ae := netip.ParseAddr(value); ae == nil && a.Zone() == "" && !a.Is4In6() {
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
			e = nil
		}
	}
	if e != nil || !p.IsValid() || p.Bits() == 0 || p.Addr().Is4In6() || !p.Addr().IsGlobalUnicast() {
		return "", errors.New("firewall allowlist requires unicast IPv4/IPv6 addresses or CIDRs; /0, loopback, multicast and unspecified addresses are not allowed")
	}
	p = p.Masked()
	if !p.Addr().IsGlobalUnicast() {
		return "", errors.New("firewall CIDR includes an unspecified or reserved base address")
	}
	return p.String(), nil
}
func firewallPort(protocol string, port int) string { return protocol + "/" + strconv.Itoa(port) }
func (r *Runtime) firewallPath(name string) string  { return filepath.Join(r.cfg.DataDir, name) }
func (r *Runtime) firewallSupported() bool {
	if r.hostExec != nil {
		return true
	}
	if runtime.GOOS != "linux" {
		return false
	}
	_, e := exec.LookPath("nft")
	return e == nil
}
func (r *Runtime) firewallExec(ctx context.Context, args ...string) (string, error) {
	if r.hostExec != nil {
		return r.hostExec(ctx, "nft", args...)
	}
	if !r.firewallSupported() {
		return "", fmt.Errorf("%w: Linux nftables (nft) is required", errNetworkUnsupported)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", args...)
	var out firewallOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	e := cmd.Run()
	if e != nil {
		return out.String(), fmt.Errorf("nftables: %w: %s", e, out.String())
	}
	if out.overflow {
		return "", errors.New("nftables response exceeds 8 MiB")
	}
	return out.String(), nil
}

type firewallOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *firewallOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 8<<20 - b.Len()
	if remaining <= 0 {
		b.overflow = true
		return n, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		b.overflow = true
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

// Targets are public native TCP listeners that this Agent actually owns. A port
// with more than one binding is intentionally excluded rather than guessing.
func (r *Runtime) firewallTargets(raw []byte) []FirewallTarget {
	var cfg struct {
		Inbounds []struct {
			Tag      string          `json:"tag"`
			Listen   string          `json:"listen"`
			Port     json.RawMessage `json:"port"`
			Protocol string          `json:"protocol"`
			Stream   struct {
				Network string `json:"network"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return []FirewallTarget{}
	}
	counts := map[int]int{}
	for _, in := range cfg.Inbounds {
		var port int
		if json.Unmarshal(in.Port, &port) == nil {
			counts[port]++
		}
	}
	managed := managementPort(r.cfg.ListenAddress)
	targets := []FirewallTarget{}
	for _, in := range cfg.Inbounds {
		var port int
		if json.Unmarshal(in.Port, &port) != nil || port < 1 || port > 65535 || counts[port] != 1 || port == 22 || port == managed || r.managementPorts[port] {
			continue
		}
		if in.Protocol != "vless" && in.Protocol != "vmess" && in.Protocol != "trojan" {
			continue
		}
		if in.Stream.Network != "" && in.Stream.Network != "tcp" && in.Stream.Network != "raw" {
			continue
		}
		listen := in.Listen
		if listen == "" {
			listen = "0.0.0.0"
		}
		address, err := netip.ParseAddr(listen)
		if err != nil || !address.IsUnspecified() || address.Zone() != "" || address.Is4In6() {
			continue
		}
		listen = address.String()
		if in.Tag == "" {
			continue
		}
		targets = append(targets, FirewallTarget{Name: in.Tag, Protocol: "tcp", Port: port, Listen: listen, Kind: in.Protocol})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Port < targets[j].Port })
	return targets
}
func (r *Runtime) currentFirewallTargets() []FirewallTarget {
	if r.instance == nil {
		return []FirewallTarget{}
	}
	b, e := os.ReadFile(r.cfg.XrayConfig)
	if e != nil {
		return []FirewallTarget{}
	}
	return r.firewallTargets(b)
}

// A wildcard IPv4 listener alone does not prove that another process does not
// own this port on IPv6 (or another local address). Check every listening socket
// in the current network namespace against this Agent's own open descriptors.
func (r *Runtime) verifyFirewallPortOwnership(rules []FirewallRule, requireOwned bool) error {
	if len(rules) == 0 || r.hostExec != nil {
		return nil
	}
	if runtime.GOOS != "linux" {
		return errNetworkUnsupported
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return fmt.Errorf("cannot inspect Agent sockets: %w", err)
	}
	owned := map[string]bool{}
	for _, entry := range entries {
		target, e := os.Readlink("/proc/self/fd/" + entry.Name())
		if e == nil && strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			owned[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	wanted := map[int]bool{}
	seen := map[int]bool{}
	for _, rule := range rules {
		wanted[rule.Port] = true
	}
	for _, path := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		data, e := os.ReadFile(path)
		if e != nil {
			if os.IsNotExist(e) && strings.HasSuffix(path, "tcp6") {
				continue
			}
			return fmt.Errorf("cannot inspect local listening sockets: %w", e)
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if len(fields) < 10 {
				return errors.New("cannot parse local listening socket inventory")
			}
			if fields[3] != "0A" {
				continue
			}
			address := strings.Split(fields[1], ":")
			if len(address) != 2 {
				return errors.New("invalid local socket address")
			}
			port, e := strconv.ParseInt(address[1], 16, 32)
			if e != nil {
				return e
			}
			if !wanted[int(port)] {
				continue
			}
			if !owned[fields[9]] {
				return fmt.Errorf("port %d is also owned by another process; refusing a host-wide port restriction", port)
			}
			seen[int(port)] = true
		}
	}
	if requireOwned {
		for port := range wanted {
			if !seen[port] {
				return fmt.Errorf("port %d is not currently listening in this Agent", port)
			}
		}
	}
	return nil
}
func (r *Runtime) firewallBindings(rules []FirewallRule, raw []byte) ([]FirewallTarget, error) {
	targets := r.firewallTargets(raw)
	bindings := []FirewallTarget{}
	for _, rule := range rules {
		found := false
		for _, target := range targets {
			if target.Protocol == rule.Protocol && target.Port == rule.Port {
				bindings = append(bindings, target)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%s is not a unique public native TCP VLESS/VMess/Trojan listener owned by this Agent; SSH and management ports are excluded", firewallPort(rule.Protocol, rule.Port))
		}
	}
	return bindings, nil
}
func (r *Runtime) validateFirewallConfig(raw []byte) error {
	state, e := r.readFirewallState()
	if e != nil {
		return e
	}
	if state == nil || len(state.Rules) == 0 {
		return nil
	}
	bindings, e := r.firewallBindings(state.Rules, raw)
	if e != nil {
		return fmt.Errorf("remove the affected firewall rule before changing a protected listener: %w", e)
	}
	if !reflect.DeepEqual(bindings, state.Bindings) {
		return errors.New("remove the affected firewall rule before changing its protected listener binding")
	}
	return nil
}
func (r *Runtime) readFirewallFile(name string) (*firewallState, error) {
	path := r.firewallPath(name)
	if e := noSymlinks(path); e != nil {
		return nil, e
	}
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if len(b) > 1<<20 {
		return nil, errors.New("firewall state exceeds 1 MiB")
	}
	var state firewallState
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&state); e != nil {
		return nil, e
	}
	owner, e := hex.DecodeString(state.Owner)
	if state.Version != 1 || e != nil || len(owner) != 32 {
		return nil, errors.New("invalid firewall state ownership")
	}
	req, e := decodeFirewall(map[string]any{"revision": state.Revision, "rules": state.Rules})
	if e != nil {
		return nil, e
	}
	if !reflect.DeepEqual(req.Rules, state.Rules) {
		return nil, errors.New("noncanonical persisted firewall rules")
	}
	if len(state.Bindings) != len(state.Rules) {
		return nil, errors.New("invalid persisted firewall bindings")
	}
	return &state, nil
}
func (r *Runtime) readFirewallState() (*firewallState, error) {
	if pending, e := r.readFirewallFile("firewall-pending.json"); e != nil || pending != nil {
		return pending, e
	}
	return r.readFirewallFile("firewall.json")
}
func (r *Runtime) saveFirewallFile(name string, state *firewallState) error {
	b, e := json.Marshal(state)
	if e != nil {
		return e
	}
	if e = atomicWrite(r.firewallPath(name), b, 0600); e != nil {
		return e
	}
	if e = r.syncFirewallDirectory(); e != nil {
		return firewallDirectorySyncError{e}
	}
	return nil
}
func firewallOwner(state *firewallState) string { return "ASWired allowlist v1 " + state.Owner }
func firewallAtoms(state *firewallState) []firewallAtom {
	result := []firewallAtom{}
	if state == nil {
		return result
	}
	for _, rule := range state.Rules {
		for _, cidr := range rule.AllowedCIDRs {
			result = append(result, firewallAtom{rule.Protocol, rule.Port, cidr, "accept"})
		}
		result = append(result, firewallAtom{rule.Protocol, rule.Port, "", "drop"})
	}
	return result
}
func firewallMatch(left any, right any) map[string]any {
	return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
}
func firewallMeta(key string) any { return map[string]any{"meta": map[string]any{"key": key}} }
func firewallPayload(protocol, field string) any {
	return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
}
func firewallBatch(state *firewallState, exists bool) ([]byte, error) {
	commands := []any{}
	if exists {
		commands = append(commands, map[string]any{"delete": map[string]any{"table": map[string]any{"family": "inet", "name": firewallTable}}})
	}
	if state != nil && len(state.Rules) > 0 {
		commands = append(commands, map[string]any{"create": map[string]any{"table": map[string]any{"family": "inet", "name": firewallTable, "comment": firewallOwner(state)}}})
		// nft 1.0.2 ignores table comments. An empty regular chain preserves the
		// installation token across versions without adding a packet hook.
		commands = append(commands, map[string]any{"add": map[string]any{"chain": map[string]any{"family": "inet", "table": firewallTable, "name": "owner_" + state.Owner}}})
		commands = append(commands, map[string]any{"add": map[string]any{"chain": map[string]any{"family": "inet", "table": firewallTable, "name": "input", "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}}})
		for _, atom := range firewallAtoms(state) {
			expr := []any{}
			if atom.CIDR != "" {
				p, _ := netip.ParsePrefix(atom.CIDR)
				family := "ipv6"
				if p.Addr().Is4() {
					family = "ipv4"
				}
				expr = append(expr, firewallMatch(firewallMeta("nfproto"), family))
			}
			expr = append(expr, firewallMatch(firewallMeta("l4proto"), atom.Protocol), firewallMatch(firewallPayload(atom.Protocol, "dport"), atom.Port))
			if atom.CIDR != "" {
				p, _ := netip.ParsePrefix(atom.CIDR)
				family := "ip6"
				if p.Addr().Is4() {
					family = "ip"
				}
				expr = append(expr, firewallMatch(firewallPayload(family, "saddr"), map[string]any{"prefix": map[string]any{"addr": p.Addr().String(), "len": p.Bits()}}))
			}
			expr = append(expr, map[string]any{atom.Verdict: nil})
			commands = append(commands, map[string]any{"add": map[string]any{"rule": map[string]any{"family": "inet", "table": firewallTable, "chain": "input", "expr": expr}}})
		}
	}
	return json.Marshal(map[string]any{"nftables": commands})
}
func jsonMap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func jsonString(v any) string      { s, _ := v.(string); return s }
func jsonInt(v any) int {
	switch n := v.(type) {
	case float64:
		if n == float64(int(n)) {
			return int(n)
		}
	case json.Number:
		i, _ := strconv.Atoi(string(n))
		return i
	}
	return -999999
}
func onlyKeys(m map[string]any, keys ...string) bool {
	for key := range m {
		found := false
		for _, allowed := range keys {
			if key == allowed {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func parseFirewallAtom(raw any) (firewallAtom, error) {
	atom := firewallAtom{}
	expr, ok := raw.([]any)
	if !ok {
		return atom, errors.New("missing firewall expressions")
	}
	var family, explicitProtocol, sourceFamily string
	havePort, haveSource := false, false
	for i, item := range expr {
		entry := jsonMap(item)
		if len(entry) != 1 {
			return atom, errors.New("unexpected firewall expression")
		}
		if verdict, ok := entry["accept"]; ok {
			if verdict != nil || i != len(expr)-1 {
				return atom, errors.New("unexpected accept")
			}
			atom.Verdict = "accept"
			continue
		}
		if verdict, ok := entry["drop"]; ok {
			if verdict != nil || i != len(expr)-1 {
				return atom, errors.New("unexpected drop")
			}
			atom.Verdict = "drop"
			continue
		}
		match := jsonMap(entry["match"])
		if len(match) != 3 || match["op"] != "==" {
			return atom, errors.New("unexpected firewall match")
		}
		left := jsonMap(match["left"])
		if len(left) != 1 {
			return atom, errors.New("unexpected match operand")
		}
		if meta := jsonMap(left["meta"]); meta != nil {
			if len(meta) != 1 {
				return atom, errors.New("unexpected meta match")
			}
			switch meta["key"] {
			case "nfproto":
				if family != "" {
					return atom, errors.New("duplicate family")
				}
				switch match["right"] {
				case "ipv4":
					family = "ip"
				case "ipv6":
					family = "ip6"
				default:
					switch jsonInt(match["right"]) {
					case 2:
						family = "ip"
					case 10:
						family = "ip6"
					default:
						return atom, errors.New("invalid address family")
					}
				}
			case "l4proto":
				if explicitProtocol != "" {
					return atom, errors.New("duplicate protocol")
				}
				switch match["right"] {
				case "tcp":
					explicitProtocol = "tcp"
				case "udp":
					explicitProtocol = "udp"
				default:
					switch jsonInt(match["right"]) {
					case 6:
						explicitProtocol = "tcp"
					case 17:
						explicitProtocol = "udp"
					default:
						return atom, errors.New("invalid protocol")
					}
				}
			default:
				return atom, errors.New("unmanaged meta match")
			}
			continue
		}
		payload := jsonMap(left["payload"])
		if len(payload) != 2 {
			return atom, errors.New("unexpected payload match")
		}
		switch payload["field"] {
		case "dport":
			if havePort || (payload["protocol"] != "tcp" && payload["protocol"] != "udp") {
				return atom, errors.New("invalid destination port match")
			}
			// nft suppresses redundant meta dependencies when printing named
			// payload expressions. The named TCP/UDP header retains the protocol
			// constraint; raw payloads are deliberately not accepted here.
			atom.Protocol = jsonString(payload["protocol"])
			atom.Port = jsonInt(match["right"])
			havePort = true
		case "saddr":
			if haveSource || (payload["protocol"] != "ip" && payload["protocol"] != "ip6") {
				return atom, errors.New("invalid source match")
			}
			sourceFamily = jsonString(payload["protocol"])
			haveSource = true
			value := jsonString(match["right"])
			if right := jsonMap(match["right"]); right != nil {
				prefix := jsonMap(right["prefix"])
				if len(right) != 1 || len(prefix) != 2 || !onlyKeys(prefix, "addr", "len") {
					return atom, errors.New("invalid source prefix")
				}
				value = jsonString(prefix["addr"]) + "/" + strconv.Itoa(jsonInt(prefix["len"]))
			}
			var e error
			atom.CIDR, e = firewallPrefix(value)
			if e != nil {
				return atom, e
			}
			p, _ := netip.ParsePrefix(atom.CIDR)
			if (sourceFamily == "ip") != p.Addr().Is4() {
				return atom, errors.New("source family mismatch")
			}
		default:
			return atom, errors.New("unmanaged payload match")
		}
	}
	if (explicitProtocol != "" && explicitProtocol != atom.Protocol) || (family != "" && sourceFamily != "" && family != sourceFamily) {
		return atom, errors.New("explicit protocol or address family contradicts named payload")
	}
	if !havePort || atom.Port < 1 || atom.Port > 65535 || (atom.Verdict == "accept" && !haveSource) || (atom.Verdict == "drop" && (haveSource || family != "")) || atom.Verdict == "" {
		return atom, errors.New("incomplete firewall rule")
	}
	return atom, nil
}
func (r *Runtime) observeFirewall(ctx context.Context) (firewallObserved, error) {
	observed := firewallObserved{Valid: true, Atoms: []firewallAtom{}}
	output, e := r.firewallExec(ctx, "-j", "list", "tables", "inet")
	if e != nil {
		return observed, e
	}
	var listing struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if json.Unmarshal([]byte(output), &listing) != nil {
		return observed, errors.New("invalid nftables table inventory")
	}
	for _, entry := range listing.NFTables {
		table := jsonMap(entry["table"])
		if table["family"] == "inet" && table["name"] == firewallTable {
			observed.Exists = true
		}
	}
	if !observed.Exists {
		return observed, nil
	}
	output, e = r.firewallExec(ctx, "-j", "list", "table", "inet", firewallTable)
	if e != nil {
		return observed, e
	}
	if json.Unmarshal([]byte(output), &listing) != nil {
		return observed, errors.New("invalid nftables table response")
	}
	tables, chains, owners := 0, 0, 0
	var owner, comment string
	hasComment, ownerHasRules := false, false
	for _, entry := range listing.NFTables {
		if _, ok := entry["metainfo"]; ok {
			continue
		}
		if len(entry) != 1 {
			observed.Valid = false
			continue
		}
		if table := jsonMap(entry["table"]); table != nil {
			tables++
			comment = jsonString(table["comment"])
			_, hasComment = table["comment"]
			if table["family"] != "inet" || table["name"] != firewallTable || !onlyKeys(table, "family", "name", "handle", "comment") {
				observed.Valid = false
			}
			continue
		}
		if chain := jsonMap(entry["chain"]); chain != nil {
			name := jsonString(chain["name"])
			if strings.HasPrefix(name, "owner_") {
				owners++
				token := strings.TrimPrefix(name, "owner_")
				decoded, decodeErr := hex.DecodeString(token)
				if decodeErr != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != token || chain["family"] != "inet" || chain["table"] != firewallTable || !onlyKeys(chain, "family", "table", "name", "handle") {
					observed.Valid = false
				} else {
					owner = "ASWired allowlist v1 " + token
				}
				continue
			}
			chains++
			if chain["family"] != "inet" || chain["table"] != firewallTable || chain["name"] != "input" || chain["type"] != "filter" || chain["hook"] != "input" || jsonInt(chain["prio"]) != -10 || chain["policy"] != "accept" || !onlyKeys(chain, "family", "table", "name", "handle", "type", "hook", "prio", "policy") {
				observed.Valid = false
			}
			continue
		}
		if rule := jsonMap(entry["rule"]); rule != nil {
			if strings.HasPrefix(jsonString(rule["chain"]), "owner_") {
				ownerHasRules = true
			}
			if rule["family"] != "inet" || rule["table"] != firewallTable || rule["chain"] != "input" || !onlyKeys(rule, "family", "table", "chain", "handle", "expr") {
				observed.Valid = false
			}
			atom, e := parseFirewallAtom(rule["expr"])
			if e != nil {
				observed.Valid = false
			} else {
				observed.Atoms = append(observed.Atoms, atom)
			}
			continue
		}
		observed.Valid = false
	}
	if tables != 1 || chains != 1 || owners != 1 || owner == "" || ownerHasRules || (hasComment && comment != owner) {
		observed.Valid = false
	}
	// No comment-only fallback: another application's same-named table must
	// never become manageable merely because nft omitted its metadata.
	if tables == 1 && owners == 1 && owner != "" && !ownerHasRules && (!hasComment || comment == owner) {
		observed.Owner = owner
	}
	return observed, nil
}
func firewallMatches(observed firewallObserved, state *firewallState) bool {
	if state == nil || len(state.Rules) == 0 {
		return !observed.Exists
	}
	return observed.Exists && observed.Valid && observed.Owner == firewallOwner(state) && reflect.DeepEqual(observed.Atoms, firewallAtoms(state))
}
func (r *Runtime) checkFirewallOwnership(observed firewallObserved, state *firewallState) error {
	if observed.Exists && (state == nil || observed.Owner != firewallOwner(state)) {
		return errors.New("refusing to modify aswired_allowlist: live table has no matching ASWired ownership proof")
	}
	return nil
}
func (r *Runtime) runFirewallBatch(ctx context.Context, state *firewallState, observed firewallObserved, check bool) error {
	if !observed.Exists && (state == nil || len(state.Rules) == 0) {
		return nil
	}
	b, e := firewallBatch(state, observed.Exists)
	if e != nil {
		return e
	}
	path := r.firewallPath("firewall-candidate.json")
	if e = atomicWrite(path, b, 0600); e != nil {
		return e
	}
	defer os.Remove(path)
	args := []string{"-j", "-f", path}
	if check {
		args = append([]string{"-c"}, args...)
	}
	_, e = r.firewallExec(ctx, args...)
	return e
}
func (r *Runtime) firewallStatus(ctx context.Context) (map[string]any, error) {
	state, e := r.readFirewallState()
	data := map[string]any{"supported": r.firewallSupported(), "backend": "nftables", "revision": uint64(0), "rules": []FirewallRule{}, "targets": r.currentFirewallTargets(), "applied": false, "checkedAt": time.Now().UTC().Format(time.RFC3339Nano)}
	if state != nil {
		data["revision"] = state.Revision
		data["rules"] = state.Rules
	}
	if e == nil && !r.firewallSupported() {
		e = fmt.Errorf("%w: install nftables on a Linux host to enable port allowlists", errNetworkUnsupported)
	}
	if e == nil {
		var observed firewallObserved
		observed, e = r.observeFirewall(ctx)
		if e == nil {
			if e = r.checkFirewallOwnership(observed, state); e == nil {
				data["applied"] = firewallMatches(observed, state)
				if !data["applied"].(bool) {
					e = errors.New("live nftables rules differ from the saved allowlist; reapply the saved policy")
				}
			}
		}
	}
	if e != nil {
		data["lastError"] = e.Error()
		if state != nil {
			r.firewallReady = false
		}
	}
	r.firewallStatusCache = data
	// Status remains a readable result even when the platform is unsupported.
	return data, nil
}
func (r *Runtime) ensureFirewall(ctx context.Context) error {
	if r.firewallReady {
		return nil
	}
	state, e := r.readFirewallState()
	if e != nil {
		return fmt.Errorf("restore firewall: %w", e)
	}
	if state == nil {
		r.firewallReady = true
		return nil
	}
	if e = r.verifyFirewallPortOwnership(state.Rules, false); e != nil {
		return e
	}
	if len(state.Rules) > 0 {
		raw, re := os.ReadFile(r.cfg.XrayConfig)
		if re != nil {
			return re
		}
		if e = r.validateFirewallConfig(raw); e != nil {
			return e
		}
	}
	observed, e := r.observeFirewall(ctx)
	if e != nil {
		return e
	}
	if e = r.checkFirewallOwnership(observed, state); e != nil {
		return e
	}
	if !firewallMatches(observed, state) {
		if e = r.runFirewallBatch(ctx, state, observed, true); e != nil {
			return e
		}
		if e = r.runFirewallBatch(ctx, state, observed, false); e != nil {
			return e
		}
	}
	verified, e := r.observeFirewall(ctx)
	if e != nil || !firewallMatches(verified, state) {
		if e == nil {
			e = errors.New("restored firewall could not be verified")
		}
		return e
	}
	if e = r.saveFirewallFile("firewall.json", state); e != nil {
		_, e = r.firewallPersistenceFailure(ctx, e)
		return e
	}
	if e = r.removeFirewallJournal(); e != nil {
		_, e = r.firewallPersistenceFailure(ctx, e)
		return e
	}
	r.firewallReady = true
	_, _ = r.firewallStatus(ctx)
	return nil
}
func (r *Runtime) applyFirewall(ctx context.Context, params map[string]any) (map[string]any, error) {
	req, e := decodeFirewall(params)
	if e != nil {
		return nil, e
	}
	old, e := r.readFirewallState()
	if e != nil {
		return nil, e
	}
	if old != nil {
		if req.Revision < old.Revision {
			return nil, errors.New("firewall revision is stale")
		}
		if req.Revision == old.Revision && !reflect.DeepEqual(req.Rules, old.Rules) {
			return nil, errors.New("firewall revision conflicts with a different saved policy")
		}
	}
	bindings := []FirewallTarget{}
	if len(req.Rules) > 0 {
		raw, re := os.ReadFile(r.cfg.XrayConfig)
		if re != nil {
			return nil, re
		}
		bindings, e = r.firewallBindings(req.Rules, raw)
		if e != nil {
			return nil, e
		}
	}
	for _, binding := range bindings {
		retained := false
		if old != nil {
			for _, previous := range old.Bindings {
				if previous.Protocol == binding.Protocol && previous.Port == binding.Port {
					if previous != binding {
						return nil, errors.New("remove the affected firewall rule before changing its protected listener binding")
					}
					retained = true
					break
				}
			}
		}
		if !retained && r.instance == nil {
			return nil, errors.New("the native Xray core must be running before protecting a new listener")
		}
	}
	if e = r.verifyFirewallPortOwnership(req.Rules, r.instance != nil); e != nil {
		return nil, e
	}
	owner := ""
	if old != nil {
		owner = old.Owner
	} else {
		token := make([]byte, 32)
		if _, e = rand.Read(token); e != nil {
			return nil, e
		}
		owner = hex.EncodeToString(token)
	}
	next := &firewallState{Version: 1, Owner: owner, Revision: req.Revision, Rules: req.Rules, Bindings: bindings}
	observed, e := r.observeFirewall(ctx)
	if e != nil {
		return nil, e
	}
	if e = r.checkFirewallOwnership(observed, old); e != nil {
		return nil, e
	}
	if old != nil && req.Revision == old.Revision && firewallMatches(observed, old) {
		if e = r.saveFirewallFile("firewall.json", old); e != nil {
			return r.firewallPersistenceFailure(ctx, e)
		}
		if e = r.removeFirewallJournal(); e != nil {
			return r.firewallPersistenceFailure(ctx, e)
		}
		r.firewallReady = true
		return r.firewallStatus(ctx)
	}
	if e = r.runFirewallBatch(ctx, next, observed, true); e != nil {
		return nil, e
	}
	if e = r.saveFirewallFile("firewall-pending.json", next); e != nil {
		return r.firewallPersistenceFailure(ctx, e)
	}
	rollback := func(cause error) (map[string]any, error) {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		current, re := r.observeFirewall(rollbackCtx)
		if re == nil {
			re = r.checkFirewallOwnership(current, next)
		}
		if re == nil {
			re = r.runFirewallBatch(rollbackCtx, old, current, false)
		}
		if re == nil {
			current, re = r.observeFirewall(rollbackCtx)
			if re == nil && !firewallMatches(current, old) {
				re = errors.New("last-good firewall verification failed")
			}
		}
		if re == nil && old != nil {
			re = r.saveFirewallFile("firewall.json", old)
		}
		if re == nil {
			re = r.removeFirewallJournal()
		}
		r.firewallReady = re == nil
		data, _ := r.firewallStatus(rollbackCtx)
		data["applied"] = false
		if re != nil {
			// A successful removal/relaxation followed by a failed verification
			// must not leave an already-running proxy exposed while claiming a
			// failed task. Keep the controller channel alive but close listeners.
			if stopErr := r.stop(rollbackCtx); stopErr != nil {
				re = fmt.Errorf("%w; stopping proxy listeners also failed: %v", re, stopErr)
			}
			cause = fmt.Errorf("%w; recovery incomplete, listener startup remains blocked: %v", cause, re)
		} else {
			data["recovery"] = "previous firewall retained"
		}
		data["lastError"] = cause.Error()
		r.firewallStatusCache = data
		return data, cause
	}
	if e = r.runFirewallBatch(ctx, next, observed, false); e != nil {
		return rollback(e)
	}
	verified, e := r.observeFirewall(ctx)
	if e != nil {
		return rollback(e)
	}
	if !firewallMatches(verified, next) {
		return rollback(errors.New("applied firewall differs from the requested rules"))
	}
	if e = r.saveFirewallFile("firewall.json", next); e != nil {
		// Rename may already have succeeded before its directory sync failed.
		// Keep the pending intent and close listeners instead of rolling the
		// kernel back while a newer committed file may survive a reboot.
		var syncErr firewallDirectorySyncError
		if errors.As(e, &syncErr) {
			return r.firewallPersistenceFailure(ctx, e)
		}
		return rollback(e)
	}
	if e = r.removeFirewallJournal(); e != nil {
		return r.firewallPersistenceFailure(ctx, fmt.Errorf("firewall applied but pending journal cleanup failed: %w", e))
	}
	r.firewallReady = true
	return r.firewallStatus(ctx)
}

func firewallStartsListener(action string) bool {
	switch action {
	case "core.start", "core.restart", "core.config.apply", "core.config.restore", "core.users.sync", "mihomo.start", "mihomo.restart", "mihomo.config.apply", "mihomo.users.sync", "network.forward.apply":
		return true
	}
	return false
}
