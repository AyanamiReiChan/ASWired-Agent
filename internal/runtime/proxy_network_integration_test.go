package runtime

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	stdruntime "runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	statscommand "github.com/xtls/xray-core/app/stats/command"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// IPv6 loopback is required on the Linux release runners. Unsupported developer
// hosts can skip the IPv6 transport cases without skipping the IPv4/routing/API cases.
func proxyGuardIPv6Unavailable(t *testing.T, err error) {
	t.Helper()
	if stdruntime.GOOS == "linux" {
		t.Fatalf("release test requires IPv6 loopback: %v", err)
	}
	t.Skipf("IPv6 loopback unavailable: %v", err)
}

func proxyGuardTarget(t *testing.T, ipv6 bool) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "proxy-network-guard-ok")
	}))
	if ipv6 {
		listener, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			server.Close()
			proxyGuardIPv6Unavailable(t, err)
		}
		_ = server.Listener.Close()
		server.Listener = listener
	}
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func proxyGuardConfig(port int) map[string]any {
	return map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"inbounds":  []any{map[string]any{"tag": "business-entry", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "UseIP"}}},
		"dns":       map[string]any{"hosts": map[string]any{"dual.test": []string{"127.0.0.1", "::1"}, "v6.test": []string{"::1"}, "blocked.test": []string{"127.0.0.1"}}},
	}
}

func proxyGuardURL(host string, port int) string {
	return "http://" + net.JoinHostPort(host, fmt.Sprint(port)) + "/"
}

func proxyGuardRequest(t *testing.T, socksPort int, url string, allowed bool) {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(socksPort)), nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get(url)
	if response != nil {
		defer response.Body.Close()
	}
	if !allowed {
		if err == nil {
			t.Fatalf("forbidden proxy request reached target: %s (status %d)", url, response.StatusCode)
		}
		return
	}
	if err != nil {
		t.Fatalf("allowed proxy request failed for %s: %v", url, err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "proxy-network-guard-ok" {
		t.Fatalf("unexpected response for %s: %q (%v)", url, body, err)
	}
}

func TestProxyIPv6GuardActualIPv4AndDomainRouting(t *testing.T) {
	target := proxyGuardTarget(t, false)
	targetPort := target.Listener.Addr().(*net.TCPAddr).Port
	r := newTestRuntime(t)
	port := freePort(t)
	cfg := proxyGuardConfig(port)
	command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": true})
	proxyGuardRequest(t, port, target.URL, true)
	proxyGuardRequest(t, port, proxyGuardURL("dual.test", targetPort), true)
	// Domain-based selection must run against the original domain, not the
	// guard's resolved IPv4 address. Everything except dual.test is blocked.
	cfg["outbounds"] = []any{map[string]any{"tag": "block", "protocol": "blackhole"}, map[string]any{"tag": "direct", "protocol": "freedom"}}
	cfg["routing"] = map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "domain": []string{"full:dual.test"}, "outboundTag": "direct"}}}
	command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": true})
	proxyGuardRequest(t, port, proxyGuardURL("dual.test", targetPort), true)
	proxyGuardRequest(t, port, proxyGuardURL("blocked.test", targetPort), false)
	proxyGuardRequest(t, port, target.URL, false)
}

func TestProxyIPv6GuardActualIPv6ToggleAndRestore(t *testing.T) {
	target := proxyGuardTarget(t, true)
	targetPort := target.Listener.Addr().(*net.TCPAddr).Port
	r := newTestRuntime(t)
	port := freePort(t)
	cfg := proxyGuardConfig(port)
	command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": false})
	// Positive controls prove both endpoints are reachable before rejection.
	proxyGuardRequest(t, port, target.URL, true)
	proxyGuardRequest(t, port, proxyGuardURL("v6.test", targetPort), true)
	command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": true})
	proxyGuardRequest(t, port, target.URL, false)
	proxyGuardRequest(t, port, proxyGuardURL("v6.test", targetPort), false)

	for _, historyPolicy := range []string{"legacy", "disabled"} {
		t.Run(historyPolicy, func(t *testing.T) {
			if historyPolicy == "disabled" {
				cfg["aswired"] = map[string]any{"blockProxyIPv6": false}
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			name := "guard-" + historyPolicy + ".json"
			if err := os.MkdirAll(filepath.Join(r.cfg.DataDir, "history"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(r.cfg.DataDir, "history", name), data, 0600); err != nil {
				t.Fatal(err)
			}
			command(t, r, "core.config.restore", map[string]any{"name": name, "blockProxyIPv6": true})
			proxyGuardRequest(t, port, target.URL, false)
			proxyGuardRequest(t, port, proxyGuardURL("v6.test", targetPort), false)
			command(t, r, "core.restart", nil)
			proxyGuardRequest(t, port, target.URL, false)
		})
	}
}

func TestProxyIPv6GuardPreservesActualAPIInbound(t *testing.T) {
	r := newTestRuntime(t)
	port, apiPort := freePort(t), freePort(t)
	cfg := proxyGuardConfig(port)
	cfg["api"] = map[string]any{"tag": "api", "services": []string{"StatsService"}}
	cfg["stats"] = map[string]any{}
	cfg["inbounds"] = append(cfg["inbounds"].([]any), map[string]any{"tag": "api", "listen": "127.0.0.1", "port": apiPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "::1", "network": "tcp"}})
	cfg["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"}}}
	command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": true})
	client, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", fmt.Sprint(apiPort)), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := statscommand.NewStatsServiceClient(client).QueryStats(ctx, &statscommand.QueryStatsRequest{Reset_: false}); err != nil {
		t.Fatalf("API inbound was broken by business IPv6 guard: %v", err)
	}
}

func TestProxyIPv6GuardPreservesActualIPv6DNSInfrastructure(t *testing.T) {
	packet, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		proxyGuardIPv6Unavailable(t, err)
	}
	var queries atomic.Int32
	dnsServer := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		for _, question := range request.Question {
			if question.Name == "via-dns.test." && question.Qtype == dns.TypeA {
				response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("127.0.0.1")})
			}
		}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = dnsServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = dnsServer.Shutdown(); _ = packet.Close() })
	target := proxyGuardTarget(t, false)
	r := newTestRuntime(t)
	port := freePort(t)
	cfg := proxyGuardConfig(port)
	cfg["dns"] = map[string]any{"tag": "internal-dns", "servers": []any{map[string]any{"address": "::1", "port": packet.LocalAddr().(*net.UDPAddr).Port}}}
	command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": true})
	proxyGuardRequest(t, port, proxyGuardURL("via-dns.test", target.Listener.Addr().(*net.TCPAddr).Port), true)
	if queries.Load() == 0 {
		t.Fatal("request did not use the IPv6 DNS fixture")
	}
}

func TestProxyIPv6GuardPreservesActualNestedIPv6RelayEndpoints(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		proxyGuardIPv6Unavailable(t, err)
	}
	relayPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	target := proxyGuardTarget(t, false)
	relay := newTestRuntime(t)
	relayCfg := proxyGuardConfig(relayPort)
	relayCfg["inbounds"].([]any)[0].(map[string]any)["listen"] = "::1"
	command(t, relay, "core.config.apply", map[string]any{"config": relayCfg, "blockProxyIPv6": true})
	for _, address := range []string{"::1", "relay.test"} {
		t.Run(address, func(t *testing.T) {
			r := newTestRuntime(t)
			port := freePort(t)
			cfg := proxyGuardConfig(port)
			cfg["dns"].(map[string]any)["hosts"].(map[string]any)["relay.test"] = []string{"::1"}
			cfg["outbounds"] = []any{
				map[string]any{"tag": "via-relay", "protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": address, "port": relayPort}}}, "streamSettings": map[string]any{"sockopt": map[string]any{"dialerProxy": "relay-transport"}}},
				map[string]any{"tag": "relay-transport", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "UseIP"}},
			}
			command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": true})
			proxyGuardRequest(t, port, target.URL, true)
			proxyGuardRequest(t, port, proxyGuardURL("dual.test", target.Listener.Addr().(*net.TCPAddr).Port), true)
		})
	}
}

func TestProxyIPv6GuardActualUDPChangedDestination(t *testing.T) {
	target6, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		proxyGuardIPv6Unavailable(t, err)
	}
	t.Cleanup(func() { _ = target6.Close() })
	target4, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target4.Close() })
	var received6 atomic.Int32
	for _, target := range []net.PacketConn{target4, target6} {
		go func() {
			data := make([]byte, 2048)
			for {
				n, from, err := target.ReadFrom(data)
				if err != nil {
					return
				}
				if target == target6 {
					received6.Add(1)
				}
				_, _ = target.WriteTo(data[:n], from)
			}
		}()
	}
	r := newTestRuntime(t)
	port := freePort(t)
	cfg := proxyGuardConfig(port)
	cfg["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["udp"] = true
	openUDP := func() net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("udp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	exchange := func(conn net.Conn, target net.Addr, allowed bool) {
		t.Helper()
		address := target.(*net.UDPAddr)
		packet := []byte{0, 0, 0}
		if ip := address.IP.To4(); ip != nil {
			packet = append(append(packet, 1), ip...)
		} else {
			packet = append(append(packet, 4), address.IP.To16()...)
		}
		packet = binary.BigEndian.AppendUint16(packet, uint16(address.Port))
		packet = append(packet, []byte("proxy-network-udp-ok")...)
		if _, err := conn.Write(packet); err != nil {
			t.Fatal(err)
		}
		deadline := 2 * time.Second
		if !allowed {
			deadline = 250 * time.Millisecond
		}
		_ = conn.SetReadDeadline(time.Now().Add(deadline))
		response := make([]byte, 2048)
		n, err := conn.Read(response)
		if !allowed {
			if err == nil {
				t.Fatalf("blocked IPv6 UDP response received: %x", response[:n])
			}
			return
		}
		if err != nil || !strings.HasSuffix(string(response[:n]), "proxy-network-udp-ok") {
			t.Fatalf("allowed UDP exchange failed: %v (%x)", err, response[:n])
		}
	}
	command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": false})
	unguarded := openUDP()
	exchange(unguarded, target4.LocalAddr(), true)
	exchange(unguarded, target6.LocalAddr(), true)
	baseline := received6.Load()
	command(t, r, "core.config.apply", map[string]any{"config": cfg, "blockProxyIPv6": true})
	conn := openUDP()
	exchange(conn, target4.LocalAddr(), true)
	// The second packet shares the SOCKS UDP session: it must not inherit the
	// first packet's allowed IPv4 target and bypass destination validation.
	exchange(conn, target6.LocalAddr(), false)
	if received6.Load() != baseline {
		t.Fatal("IPv6 UDP payload reached target after an allowed IPv4 packet")
	}
}
