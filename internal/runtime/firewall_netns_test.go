package runtime

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
)

// This test must run only in a newly created network namespace. It never uses
// the host namespace even when a developer accidentally sets the opt-in flag.
func TestFirewallNetNS(t *testing.T) {
	if os.Getenv("ASWIRED_FIREWALL_NETNS") != "1" {
		t.Skip("set ASWIRED_FIREWALL_NETNS=1 inside an isolated Linux network namespace")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("firewall integration requires Linux root in an isolated network namespace")
	}
	self, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	if self == host {
		t.Fatal("refusing to modify the host network namespace")
	}
	for _, binary := range []string{"nft", "ip"} {
		if _, e := exec.LookPath(binary); e != nil {
			t.Fatalf("required integration dependency %s: %v", binary, e)
		}
	}
	run := func(binary string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, e := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %v: %s", binary, args, e, out)
		}
		return string(out)
	}
	run("ip", "link", "set", "lo", "up")
	for _, ip := range []string{"192.0.2.1/32", "192.0.2.10/32", "192.0.2.11/32"} {
		run("ip", "addr", "add", ip, "dev", "lo")
	}
	for _, ip := range []string{"2001:db8::1/128", "2001:db8::10/128", "2001:db8::11/128"} {
		run("ip", "-6", "addr", "add", ip, "dev", "lo", "nodad")
	}
	run("nft", "add", "table", "inet", "aswired_firewall_test_foreign")
	foreignBefore := run("nft", "-j", "list", "table", "inet", "aswired_firewall_test_foreign")
	defer run("nft", "delete", "table", "inet", "aswired_firewall_test_foreign")
	defer func() { _ = exec.Command("nft", "delete", "table", "inet", firewallTable).Run() }()

	echo, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			conn, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	r := newTestRuntime(t)
	port4, port6 := freePort(t), freePort(t)
	for port6 == port4 {
		port6 = freePort(t)
	}
	config := firewallTestConfig(port4, "0.0.0.0")
	six := firewallTestConfig(port6, "::")["inbounds"].([]any)[0].(map[string]any)
	six["tag"] = "customer-vless-ipv6"
	six["streamSettings"].(map[string]any)["sockopt"] = map[string]any{"v6only": true}
	config["inbounds"] = append(config["inbounds"].([]any), six)
	command(t, r, "core.config.apply", map[string]any{"config": config})
	request := func(revision int, allowed ...string) map[string]any {
		return map[string]any{"revision": revision, "rules": []FirewallRule{{ID: "client-v4", Protocol: "tcp", Port: port4, AllowedCIDRs: allowed}, {ID: "client-v6", Protocol: "tcp", Port: port6, AllowedCIDRs: allowed}}}
	}
	dial := func(source, destination string, port int) (net.Conn, error) {
		return (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}, Timeout: 300 * time.Millisecond}).Dial("tcp", net.JoinHostPort(destination, strconv.Itoa(port)))
	}
	// A different process can own IPv4:port even while this Agent owns IPv6:port.
	// Explicit v6only above avoids Go's default dual-stack wildcard listener.
	child := exec.Command(os.Args[0], "-test.run=^TestFirewallForeignListenerChild$")
	child.Env = append(os.Environ(), "ASWIRED_FIREWALL_CHILD_LISTEN=0.0.0.0:"+strconv.Itoa(port6))
	stdout, e := child.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdin, e := child.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	childStopped := false
	defer func() {
		if !childStopped {
			stdin.Close()
			child.Process.Kill()
			child.Wait()
		}
	}()
	ready, e := bufio.NewReader(stdout).ReadString('\n')
	if e != nil || strings.TrimSpace(ready) != "READY" {
		t.Fatalf("foreign listener startup failed: %q %v", ready, e)
	}
	denied := r.Handle(context.Background(), wire.Command{Action: "network.firewall.apply", Params: request(1, "192.0.2.10", "2001:db8::10")})
	if denied.Status != "failed" || !strings.Contains(denied.Error, "another process") {
		t.Fatalf("foreign same-port IPv4 socket was not protected: %+v", denied)
	}
	stdin.Close()
	if e = child.Wait(); e != nil {
		t.Fatal(e)
	}
	childStopped = true

	command(t, r, "network.firewall.apply", request(1, "192.0.2.10", "2001:db8::10"))
	for _, route := range []struct {
		source, destination string
		port                int
	}{{"192.0.2.10", "192.0.2.1", port4}, {"2001:db8::10", "2001:db8::1", port6}} {
		conn, e := dial(route.source, route.destination, route.port)
		if e != nil {
			t.Fatalf("allowed source rejected: %+v %v", route, e)
		}
		conn.Close()
	}
	for _, route := range []struct {
		source, destination string
		port                int
	}{{"192.0.2.11", "192.0.2.1", port4}, {"2001:db8::11", "2001:db8::1", port6}} {
		if conn, e := dial(route.source, route.destination, route.port); e == nil {
			conn.Close()
			t.Fatalf("denied source accepted: %+v", route)
		}
	}
	conn, e := dial("192.0.2.11", "127.0.0.1", echo.Addr().(*net.TCPAddr).Port)
	if e != nil {
		t.Fatalf("unrelated service was restricted: %v", e)
	}
	conn.Close()
	// Establish a real VLESS TCP stream, then revoke its source address. There
	// must be no ct established accept rule ahead of the managed port restriction.
	live, e := dial("192.0.2.10", "192.0.2.1", port4)
	if e != nil {
		t.Fatal(e)
	}
	defer live.Close()
	live.SetDeadline(time.Now().Add(2 * time.Second))
	id, _ := hex.DecodeString("82d5832bef174e7d951239fbdcb247b3")
	header := append([]byte{0}, id...)
	header = append(header, 0, 1)
	header = binary.BigEndian.AppendUint16(header, uint16(echo.Addr().(*net.TCPAddr).Port))
	header = append(header, 1, 127, 0, 0, 1)
	header = append(header, []byte("ping")...)
	if _, e = live.Write(header); e != nil {
		t.Fatal(e)
	}
	response := make([]byte, 6)
	if _, e = io.ReadFull(live, response); e != nil || string(response[2:]) != "ping" {
		t.Fatalf("real VLESS stream failed: %x %v", response, e)
	}
	command(t, r, "network.firewall.apply", request(2, "192.0.2.11", "2001:db8::11"))
	live.SetDeadline(time.Now().Add(350 * time.Millisecond))
	_, _ = live.Write([]byte("deny"))
	if _, e = live.Read(make([]byte, 4)); e == nil {
		t.Fatal("revoked established source continued passing traffic")
	}
	live.Close()
	command(t, r, "network.firewall.apply", request(3, "192.0.2.10", "2001:db8::10"))
	r.Close()
	run("nft", "delete", "table", "inet", firewallTable)
	r2, e := New(r.cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer r2.Close()
	if e = r2.Start(context.Background()); e != nil {
		t.Fatalf("restore before listeners: %v", e)
	}
	status := command(t, r2, "network.firewall.status", nil)
	if status.Data["applied"] != true || status.Data["revision"] != uint64(3) {
		t.Fatal(status)
	}
	if conn, e := dial("192.0.2.11", "192.0.2.1", port4); e == nil {
		conn.Close()
		t.Fatal("restart failed to restore rejection")
	}
	command(t, r2, "network.firewall.apply", map[string]any{"revision": 4, "rules": []any{}})
	conn, e = dial("192.0.2.11", "192.0.2.1", port4)
	if e != nil {
		t.Fatal("rule removal did not restore access", e)
	}
	conn.Close()
	if after := run("nft", "-j", "list", "table", "inet", "aswired_firewall_test_foreign"); after != foreignBefore {
		t.Fatal("foreign administrator table changed")
	}
}

func TestFirewallForeignListenerChild(t *testing.T) {
	address := os.Getenv("ASWIRED_FIREWALL_CHILD_LISTEN")
	if address == "" {
		t.Skip("subprocess helper")
	}
	if os.Getenv("ASWIRED_FIREWALL_NETNS") != "1" || runtime.GOOS != "linux" {
		t.Fatal("foreign-listener helper is only available in the opted-in Linux integration test")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if self == "" || self == host {
		t.Fatal("helper refuses host network namespace")
	}
	listener, e := net.Listen("tcp4", address)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	fmt.Println("READY")
	_, _ = io.Copy(io.Discard, os.Stdin)
}
