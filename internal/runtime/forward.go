package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ForwardRule struct {
	ID             string `json:"id"`
	Protocol       string `json:"protocol"`
	Listen         string `json:"listen"`
	Target         string `json:"target"`
	UDPIdleSeconds int    `json:"udp_idle_seconds,omitempty"`
}
type forwardListener struct {
	generation     string
	mu             sync.Mutex
	rule           ForwardRule
	tcp            net.Listener
	udp            net.PacketConn
	stopped        bool
	connections    map[net.Conn]struct{}
	sessions       map[string]net.Conn
	received, sent atomic.Int64
	errors         atomic.Int64
}
type forwardManager struct{ listeners map[string]*forwardListener }

func newForwardManager() *forwardManager {
	return &forwardManager{listeners: map[string]*forwardListener{}}
}
func validNetworkAddress(address string, local bool) error {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return errors.New("address must be host:port")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return errors.New("port must be 1..65535")
	}
	if local {
		if net.ParseIP(host) == nil {
			return errors.New("listen requires a local IP literal")
		}
	} else if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n/\\#;=\"'") {
		return errors.New("invalid target host")
	}
	return nil
}
func decodeForwardRules(raw any) ([]ForwardRule, error) {
	if raw == nil {
		return nil, errors.New("rules array is required; use [] to remove managed forwards")
	}
	b, e := json.Marshal(raw)
	if e != nil {
		return nil, e
	}
	var rules []ForwardRule
	if e = json.Unmarshal(b, &rules); e != nil {
		return nil, e
	}
	if rules == nil || len(rules) > 256 {
		return nil, errors.New("rules must contain 0..256 items")
	}
	ids, addresses := map[string]bool{}, map[string]bool{}
	for i := range rules {
		r := &rules[i]
		if !safeName(strings.ReplaceAll(r.ID, ":", "-")) || ids[r.ID] {
			return nil, errors.New("unique safe rule id required")
		}
		ids[r.ID] = true
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return nil, errors.New("forward protocol must be tcp or udp")
		}
		if e = validNetworkAddress(r.Listen, true); e != nil {
			return nil, e
		}
		if e = validNetworkAddress(r.Target, false); e != nil {
			return nil, e
		}
		if r.Listen == r.Target {
			return nil, errors.New("forward cannot target its own listener")
		}
		key := r.Protocol + "/" + r.Listen
		if addresses[key] {
			return nil, errors.New("duplicate forward listen address")
		}
		addresses[key] = true
		if r.UDPIdleSeconds == 0 {
			r.UDPIdleSeconds = 60
		}
		if r.UDPIdleSeconds < 5 || r.UDPIdleSeconds > 600 {
			return nil, errors.New("UDP idle timeout must be 5..600 seconds")
		}
	}
	return rules, nil
}
func createForward(rule ForwardRule) (*forwardListener, error) {
	f := &forwardListener{rule: rule, connections: map[net.Conn]struct{}{}, sessions: map[string]net.Conn{}}
	identity := make([]byte, 16)
	if _, e := rand.Read(identity); e != nil {
		return nil, e
	}
	f.generation = hex.EncodeToString(identity)
	var e error
	if rule.Protocol == "tcp" {
		f.tcp, e = net.Listen("tcp", rule.Listen)
	} else {
		f.udp, e = net.ListenPacket("udp", rule.Listen)
	}
	return f, e
}
func (f *forwardListener) start() {
	if f.tcp != nil {
		go f.serveTCP()
	} else {
		go f.serveUDP()
	}
}
func (f *forwardListener) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopped {
		return
	}
	f.stopped = true
	if f.tcp != nil {
		f.tcp.Close()
	}
	if f.udp != nil {
		f.udp.Close()
	}
	for c := range f.connections {
		c.Close()
	}
	for _, c := range f.sessions {
		c.Close()
	}
}
func (f *forwardListener) currentRule() ForwardRule { f.mu.Lock(); defer f.mu.Unlock(); return f.rule }
func (f *forwardListener) serveTCP() {
	for {
		c, e := f.tcp.Accept()
		if e != nil {
			return
		}
		f.mu.Lock()
		if f.stopped {
			f.mu.Unlock()
			c.Close()
			return
		}
		if len(f.connections) >= 4096 {
			f.errors.Add(1)
			f.mu.Unlock()
			c.Close()
			continue
		}
		f.connections[c] = struct{}{}
		target := f.rule.Target
		f.mu.Unlock()
		go f.pipeTCP(c, target)
	}
}
func (f *forwardListener) pipeTCP(client net.Conn, target string) {
	defer func() { client.Close(); f.mu.Lock(); delete(f.connections, client); f.mu.Unlock() }()
	remote, e := net.DialTimeout("tcp", target, 5*time.Second)
	if e != nil {
		f.errors.Add(1)
		return
	}
	defer remote.Close()
	f.mu.Lock()
	if f.stopped {
		f.mu.Unlock()
		return
	}
	f.connections[remote] = struct{}{}
	f.mu.Unlock()
	defer func() { f.mu.Lock(); delete(f.connections, remote); f.mu.Unlock() }()
	done := make(chan struct{})
	go func() {
		_, e := io.Copy(forwardCountWriter{remote, &f.received}, client)
		if e != nil {
			f.errors.Add(1)
		}
		if c, ok := remote.(*net.TCPConn); ok {
			c.CloseWrite()
		}
		close(done)
	}()
	_, e = io.Copy(forwardCountWriter{client, &f.sent}, remote)
	if e != nil {
		f.errors.Add(1)
	}
	if c, ok := client.(*net.TCPConn); ok {
		c.CloseWrite()
	}
	client.Close()
	remote.Close()
	<-done
}
func (f *forwardListener) serveUDP() {
	b := make([]byte, 65535)
	for {
		n, from, e := f.udp.ReadFrom(b)
		if e != nil {
			return
		}
		key := from.String()
		f.mu.Lock()
		if f.stopped {
			f.mu.Unlock()
			return
		}
		conn := f.sessions[key]
		rule := f.rule
		if conn == nil {
			if len(f.sessions) >= 1024 {
				f.errors.Add(1)
				f.mu.Unlock()
				continue
			}
			conn, e = net.DialTimeout("udp", rule.Target, 3*time.Second)
			if e != nil {
				f.errors.Add(1)
				f.mu.Unlock()
				continue
			}
			f.sessions[key] = conn
			go f.readUDP(key, from, conn)
		}
		conn.SetReadDeadline(time.Now().Add(time.Duration(rule.UDPIdleSeconds) * time.Second))
		sent, e := conn.Write(b[:n])
		f.mu.Unlock()
		f.received.Add(int64(sent))
		if e != nil {
			f.errors.Add(1)
		}
	}
}
func (f *forwardListener) readUDP(key string, from net.Addr, conn net.Conn) {
	defer func() {
		conn.Close()
		f.mu.Lock()
		if f.sessions[key] == conn {
			delete(f.sessions, key)
		}
		f.mu.Unlock()
	}()
	b := make([]byte, 65535)
	for {
		n, e := conn.Read(b)
		if e != nil {
			if ne, ok := e.(net.Error); !ok || !ne.Timeout() {
				f.errors.Add(1)
			}
			return
		}
		sent, e := f.udp.WriteTo(b[:n], from)
		f.sent.Add(int64(sent))
		if e != nil {
			f.errors.Add(1)
			return
		}
	}
}
func (m *forwardManager) apply(rules []ForwardRule, persist func() error) error {
	next := map[string]*forwardListener{}
	created := []*forwardListener{}
	abandon := func() {
		for _, f := range created {
			f.close()
		}
	}
	for _, rule := range rules {
		old := m.listeners[rule.ID]
		if old != nil {
			previous := old.currentRule()
			if previous.Protocol == rule.Protocol && previous.Listen == rule.Listen {
				next[rule.ID] = old
				continue
			}
		}
		f, e := createForward(rule)
		if e != nil {
			abandon()
			return fmt.Errorf("bind rule %s: %w", rule.ID, e)
		}
		next[rule.ID] = f
		created = append(created, f)
	}
	if persist != nil {
		if e := persist(); e != nil {
			abandon()
			return e
		}
	}
	for _, rule := range rules {
		f := next[rule.ID]
		f.mu.Lock()
		if f.rule.Target != rule.Target {
			for key, conn := range f.sessions {
				conn.Close()
				delete(f.sessions, key)
			}
		}
		f.rule = rule
		f.mu.Unlock()
	}
	for id, f := range m.listeners {
		if next[id] != f {
			f.close()
		}
	}
	m.listeners = next
	for _, f := range created {
		f.start()
	}
	return nil
}
func (m *forwardManager) close() {
	for _, f := range m.listeners {
		f.close()
	}
	m.listeners = map[string]*forwardListener{}
}
func (m *forwardManager) status() map[string]any {
	items := []map[string]any{}
	for _, f := range m.listeners {
		f.mu.Lock()
		items = append(items, map[string]any{"rule": f.rule, "generation": f.generation, "listening": !f.stopped, "active_tcp_sockets": len(f.connections), "udp_sessions": len(f.sessions), "received_bytes": f.received.Load(), "sent_bytes": f.sent.Load(), "errors": f.errors.Load()})
		f.mu.Unlock()
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["rule"].(ForwardRule).ID < items[j]["rule"].(ForwardRule).ID })
	return map[string]any{"items": items, "sampled_at": time.Now().UnixMilli(), "counter_scope": "current Agent process; raw socket bytes, not user billing", "existing_tcp_sessions": "retain their previous target until closed"}
}
func (r *Runtime) applyForwards(raw any) (map[string]any, error) {
	rules, e := decodeForwardRules(raw)
	if e != nil {
		return nil, e
	}
	b, e := json.MarshalIndent(rules, "", "  ")
	if e != nil {
		return nil, e
	}
	if e = r.forwards.apply(rules, func() error { return atomicWrite(filepath.Join(r.cfg.DataDir, "forwards.json"), b, 0600) }); e != nil {
		return nil, e
	}
	out := r.forwards.status()
	out["applied"] = true
	out["persisted"] = true
	return out, nil
}
func (r *Runtime) restoreForwards() error {
	b, e := os.ReadFile(filepath.Join(r.cfg.DataDir, "forwards.json"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var raw any
	if e = json.Unmarshal(b, &raw); e != nil {
		return e
	}
	rules, e := decodeForwardRules(raw)
	if e != nil {
		return e
	}
	return r.forwards.apply(rules, nil)
}

type forwardCountWriter struct {
	writer io.Writer
	count  *atomic.Int64
}

func (w forwardCountWriter) Write(b []byte) (int, error) {
	n, e := w.writer.Write(b)
	w.count.Add(int64(n))
	return n, e
}
