package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestActualTCPUDPForwardRollbackAndRestart(t *testing.T) {
	tcp, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	udp, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udp.WriteTo(b[:n], a)
		}
	}()
	r := newTestRuntime(t)
	tcpListen := net.JoinHostPort("127.0.0.1", fmtInt(freePort(t)))
	udpListen := net.JoinHostPort("127.0.0.1", fmtInt(freePort(t)))
	rules := []any{map[string]any{"id": "tcp-rule:0", "protocol": "tcp", "listen": tcpListen, "target": tcp.Addr().String()}, map[string]any{"id": "udp-rule", "protocol": "udp", "listen": udpListen, "target": udp.LocalAddr().String()}}
	command(t, r, "network.forward.apply", map[string]any{"rules": rules})
	exchange := func(protocol, address string) {
		t.Helper()
		c, e := net.DialTimeout(protocol, address, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		payload := []byte("actual-ASWired-forward-payload")
		if _, e = c.Write(payload); e != nil {
			t.Fatal(e)
		}
		reply := make([]byte, len(payload))
		if _, e = io.ReadFull(c, reply); e != nil || !bytes.Equal(reply, payload) {
			t.Fatalf("%s forwarding failed: %v %q", protocol, e, reply)
		}
	}
	exchange("tcp", tcpListen)
	exchange("udp", udpListen)
	before, e := os.ReadFile(filepath.Join(r.cfg.DataDir, "forwards.json"))
	if e != nil {
		t.Fatal(e)
	}
	occupied, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer occupied.Close()
	bad := append(append([]any{}, rules...), map[string]any{"id": "occupied", "protocol": "tcp", "listen": occupied.Addr().String(), "target": tcp.Addr().String()})
	if result := r.Handle(context.Background(), wire.Command{Action: "network.forward.apply", Params: map[string]any{"rules": bad}}); result.Status != "failed" {
		t.Fatal("occupied listener falsely succeeded")
	}
	after, _ := os.ReadFile(filepath.Join(r.cfg.DataDir, "forwards.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("failed apply modified desired rules")
	}
	exchange("tcp", tcpListen)
	exchange("udp", udpListen)
	r.Close()
	// A process restart creates a new runtime and reopens its log managers.
	r, e = New(r.cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	if e = r.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	exchange("tcp", tcpListen)
	exchange("udp", udpListen)
	command(t, r, "network.forward.apply", map[string]any{"rules": []any{}})
	if conn, e := net.DialTimeout("tcp", tcpListen, 100*time.Millisecond); e == nil {
		conn.Close()
		t.Fatal("removed listener still accepts connections")
	}
}

func testWGSpec(id string) WireGuardSpec {
	return WireGuardSpec{ID: id, PrivateKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), Addresses: []string{"10.44.0.2/32", "fd44::2/128"}, MTU: 1420, RouteTable: 51820, Peers: []WireGuardPeer{{PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), Endpoint: "192.0.2.1:51820", AllowedIPs: []string{"0.0.0.0/0", "::/0"}, PersistentKeepalive: 25}}}
}
func wgParams(c WireGuardSpec) map[string]any {
	b, _ := json.Marshal(c)
	var p map[string]any
	json.Unmarshal(b, &p)
	return p
}
func TestWireGuardExecutionRollbackRecoveryAndSecretIsolation(t *testing.T) {
	r := newTestRuntime(t)
	spec := testWGSpec("private-tunnel")
	interfaces := map[string]string{}
	var calls []string
	failNew := false
	secretNew := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	r.hostExec = func(ctx context.Context, binary string, args ...string) (string, error) {
		call := binary + " " + strings.Join(args, " ")
		calls = append(calls, call)
		if strings.Contains(call, spec.PrivateKey) || strings.Contains(call, secretNew) {
			t.Fatal("private key leaked to process arguments")
		}
		if binary == "wg-quick" {
			path := args[1]
			name := strings.TrimSuffix(filepath.Base(path), ".conf")
			if args[0] == "down" {
				delete(interfaces, name)
				return "", nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return "", e
			}
			var key string
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "PrivateKey = ") {
					key = strings.TrimPrefix(line, "PrivateKey = ")
				}
			}
			c := spec
			c.PrivateKey = key
			interfaces[name] = wgExpectedPublic(c)
			if failNew && key == secretNew {
				return "some stderr may contain a secret", errors.New("failed")
			}
			return "", nil
		}
		if binary == "wg" {
			if len(args) == 2 && args[1] == "interfaces" {
				var names []string
				for n := range interfaces {
					names = append(names, n)
				}
				return strings.Join(names, " "), nil
			}
			name, field := args[1], args[2]
			public, ok := interfaces[name]
			if !ok {
				return "", errors.New("missing interface")
			}
			switch field {
			case "public-key":
				return public, nil
			case "endpoints":
				return spec.Peers[0].PublicKey + "\t192.0.2.1:51820", nil
			case "latest-handshakes":
				return spec.Peers[0].PublicKey + "\t1700000000", nil
			case "transfer":
				return spec.Peers[0].PublicKey + "\t123\t456", nil
			case "allowed-ips":
				return spec.Peers[0].PublicKey + "\t0.0.0.0/0,::/0", nil
			}
			t.Fatalf("unsafe unexpected wg field: %s", field)
		}
		if binary == "ip" {
			return `[{"ifname":"managed","operstate":"UNKNOWN"}]`, nil
		}
		t.Fatalf("unexpected executor: %s", call)
		return "", nil
	}
	first := command(t, r, "network.wireguard.apply", wgParams(spec))
	if first.Data["applied"] != true {
		t.Fatal("activation result missing")
	}
	configPath, _ := r.wgPaths(spec.ID)
	old, _ := os.ReadFile(configPath)
	if !bytes.Contains(old, []byte("Table = 51820")) || bytes.Contains(old, []byte("PostUp")) {
		t.Fatal("unsafe generated wg-quick configuration")
	}
	changed := spec
	changed.PrivateKey = secretNew
	failNew = true
	result := r.Handle(context.Background(), wire.Command{Action: "network.wireguard.apply", Params: wgParams(changed)})
	if result.Status != "failed" || result.Data["rollback_succeeded"] != true || interfaces[wgInterface(spec.ID)] != wgExpectedPublic(spec) {
		t.Fatalf("failed configuration did not restore old interface: %#v", result)
	}
	restored, _ := os.ReadFile(configPath)
	if !bytes.Equal(old, restored) {
		t.Fatal("old config lost")
	}
	raw, _ := json.Marshal(result)
	if bytes.Contains(raw, []byte(secretNew)) {
		t.Fatal("failure disclosed key")
	}
	state := command(t, r, "network.wireguard.status", map[string]any{"id": spec.ID})
	raw, _ = json.Marshal(state)
	if bytes.Contains(raw, []byte(spec.PrivateKey)) || state.Data["running"] != true {
		t.Fatal("status leaked key or fabricated state")
	}
	delete(interfaces, wgInterface(spec.ID))
	if e := r.restoreWireGuard(context.Background()); e != nil {
		t.Fatal(e)
	}
	if interfaces[wgInterface(spec.ID)] != wgExpectedPublic(spec) {
		t.Fatal("restart did not restore persisted tunnel")
	}
	command(t, r, "network.wireguard.remove", map[string]any{"id": spec.ID})
	if len(interfaces) != 0 {
		t.Fatal("removal left interface")
	}
	if _, e := os.Stat(configPath); !os.IsNotExist(e) {
		t.Fatal("removal left private configuration")
	}
	invalid := spec
	invalid.Peers[0].Endpoint = "192.0.2.1:51820\nPostUp = bad"
	prior := len(calls)
	if out := r.Handle(context.Background(), wire.Command{Action: "network.warp.apply", Params: wgParams(invalid)}); out.Status != "failed" || len(calls) != prior {
		t.Fatal("invalid config reached system executor")
	}
}

func TestTCPQualityUsesActualReachability(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	params := map[string]any{"method": "tcp", "target": ln.Addr().String(), "count": float64(3), "timeout_ms": float64(100)}
	out, e := networkQuality(context.Background(), params)
	if e != nil || out["successful_samples"] != 3 {
		t.Fatalf("actual TCP test failed: %v %#v", e, out)
	}
	ln.Close()
	out, e = networkQuality(context.Background(), params)
	if e != nil || out["failure_percent"] != float64(100) {
		t.Fatal("offline TCP target reported reachable")
	}
	if _, ok := out["packet_loss_percent"]; ok {
		t.Fatal("TCP connect failure labeled ICMP loss")
	}
}

type echoFixture struct {
	request     []byte
	reads       int
	protocol    int
	ip          net.IP
	datagram    bool
	destination net.Addr
	closed      bool
}

func (f *echoFixture) WriteTo(b []byte, destination net.Addr) (int, error) {
	f.request = append([]byte{}, b...)
	f.destination = destination
	return len(b), nil
}
func (f *echoFixture) ReadFrom(b []byte) (int, net.Addr, error) {
	protocol := f.protocol
	if protocol == 0 {
		protocol = 1
	}
	m, e := icmp.ParseMessage(protocol, f.request)
	if e != nil {
		return 0, nil, e
	}
	echo := m.Body.(*icmp.Echo)
	ip := f.ip
	if ip == nil {
		ip = net.ParseIP("127.0.0.1")
	}
	var replyType icmp.Type = ipv4.ICMPTypeEchoReply
	if protocol == 58 {
		replyType = ipv6.ICMPTypeEchoReply
	}
	f.reads++
	switch f.reads {
	case 1:
		echo.Seq++
	case 2:
		echo.Data[0] ^= 0xff
	case 3:
		ip = net.ParseIP("192.0.2.99")
	case 4:
		replyType = m.Type
	case 5:
		if !f.datagram {
			echo.ID ^= 0xffff
		}
	}
	if f.datagram {
		// Linux ping sockets replace the user-supplied identifier.
		echo.ID ^= 0xffff
	}
	reply := icmp.Message{Type: replyType, Body: echo}
	raw, e := reply.Marshal(nil)
	var source net.Addr = &net.IPAddr{IP: ip}
	if f.datagram {
		source = &net.UDPAddr{IP: ip}
	}
	return copy(b, raw), source, e
}
func (f *echoFixture) SetDeadline(time.Time) error { return nil }
func (f *echoFixture) Close() error                { f.closed = true; return nil }
func TestICMPMatchesAuthenticatedSampleAndPermissionFailure(t *testing.T) {
	f := &echoFixture{}
	probe, close, e := icmpProbeWith(context.Background(), "127.0.0.1", time.Second, func(string, string) (icmpSocket, error) { return f, nil })
	if e != nil {
		t.Fatal(e)
	}
	defer close()
	if _, e = probe(1); e != nil || f.reads != 6 {
		t.Fatal("ICMP accepted an unrelated reply")
	}
	_, _, e = icmpProbeWith(context.Background(), "127.0.0.1", time.Second, func(string, string) (icmpSocket, error) { return nil, os.ErrPermission })
	if !errors.Is(e, errNetworkUnsupported) {
		t.Fatal("ICMP privilege failure was not unsupported")
	}
	if !strings.Contains(e.Error(), "ping_group_range") || !strings.Contains(e.Error(), "CAP_NET_RAW") {
		t.Fatal("ICMP privilege failure lacks Linux remediation")
	}
}

func TestICMPPingSocketFallback(t *testing.T) {
	for _, tc := range []struct {
		target, rawNetwork, pingNetwork, listen string
		protocol                                int
	}{
		{"127.0.0.1", "ip4:icmp", "udp4", "0.0.0.0", 1},
		{"::1", "ip6:ipv6-icmp", "udp6", "::", 58},
	} {
		t.Run(tc.pingNetwork, func(t *testing.T) {
			f := &echoFixture{protocol: tc.protocol, ip: net.ParseIP(tc.target), datagram: true}
			calls := 0
			probe, cleanup, err := icmpProbeWith(context.Background(), tc.target, time.Second, func(network, listen string) (icmpSocket, error) {
				calls++
				if listen != tc.listen {
					t.Fatalf("unexpected listen address %q", listen)
				}
				if calls == 1 && network == tc.rawNetwork {
					return nil, os.ErrPermission
				}
				if calls != 2 || network != tc.pingNetwork {
					t.Fatalf("unexpected socket attempt %d: %s", calls, network)
				}
				return f, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			if calls != 2 {
				t.Fatalf("expected ping socket fallback, got %d attempts", calls)
			}
			if _, err = probe(1); err != nil || f.reads != 5 {
				t.Fatalf("ping reply validation failed: reads=%d err=%v", f.reads, err)
			}
			if _, err = probe(2); err != nil {
				t.Fatalf("second sample failed: %v", err)
			}
			destination, ok := f.destination.(*net.UDPAddr)
			if !ok || !destination.IP.Equal(f.ip) {
				t.Fatalf("invalid ping socket destination: %v", f.destination)
			}
			cleanup()
			if !f.closed {
				t.Fatal("ping socket was not closed")
			}
		})
	}
}
