package runtime

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

func checkPorts(ctx context.Context, p map[string]any) (map[string]any, error) {
	ports, ok := p["ports"].([]any)
	if !ok || len(ports) > 128 {
		return nil, errors.New("ports must be an array of at most 128 integers")
	}
	host, _ := p["host"].(string)
	if host == "" {
		host = "0.0.0.0"
	}
	if net.ParseIP(host) == nil {
		return nil, errors.New("host must be a local IP literal")
	}
	protocol, _ := p["protocol"].(string)
	if protocol == "" {
		protocol = "tcp"
	}
	if protocol != "tcp" && protocol != "udp" {
		return nil, errors.New("protocol must be tcp or udp")
	}
	items := []map[string]any{}
	for _, value := range ports {
		n, ok := value.(float64)
		if !ok || n < 1 || n > 65535 || n != float64(int(n)) {
			return nil, errors.New("port must be an integer between 1 and 65535")
		}
		address := net.JoinHostPort(host, strconv.Itoa(int(n)))
		var e error
		if protocol == "tcp" {
			var ln net.Listener
			ln, e = (&net.ListenConfig{}).Listen(ctx, "tcp", address)
			if ln != nil {
				ln.Close()
			}
		} else {
			var conn net.PacketConn
			conn, e = (&net.ListenConfig{}).ListenPacket(ctx, "udp", address)
			if conn != nil {
				conn.Close()
			}
		}
		item := map[string]any{"port": int(n), "protocol": protocol, "available": e == nil}
		if e != nil {
			item["error"] = e.Error()
		}
		items = append(items, item)
	}
	return map[string]any{"items": items, "reservation": false}, nil
}

func (r *Runtime) deployCertificate(p map[string]any) (map[string]any, error) {
	name, _ := p["name"].(string)
	cert, _ := p["certificate"].(string)
	key, _ := p["private_key"].(string)
	if !safeName(name) {
		return nil, errors.New("invalid certificate name")
	}
	pair, e := tls.X509KeyPair([]byte(cert), []byte(key))
	if e != nil {
		return nil, fmt.Errorf("certificate/key validation: %w", e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	if time.Now().After(leaf.NotAfter) || time.Now().Before(leaf.NotBefore) {
		return nil, errors.New("certificate is outside its validity period")
	}

	hash := sha256.Sum256(pair.Certificate[0])
	fingerprint := hex.EncodeToString(hash[:])
	dir := filepath.Join(r.cfg.DataDir, "certificates", name, fingerprint)
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if e = atomicWrite(certPath, []byte(cert), 0644); e != nil {
		return nil, e
	}
	if e = atomicWrite(keyPath, []byte(key), 0600); e != nil {
		return nil, e
	}
	return map[string]any{"deployed": true, "name": name, "fingerprint_sha256": fingerprint, "certificate_path": certPath, "private_key_path": keyPath, "not_after": leaf.NotAfter.Unix(), "dns_names": leaf.DNSNames, "service_reloaded": false}, nil
}

func (r *Runtime) applySite(ctx context.Context, p map[string]any) (map[string]any, error) {
	if r.cfg.NginxConfig == "" {
		return nil, errors.New("nginx_config must be configured locally before website management")
	}
	content, ok := p["config"].(string)
	if !ok || len(content) > 1<<20 {
		return nil, errors.New("config must be a nginx config string up to 1 MiB")
	}
	old, e := os.ReadFile(r.cfg.NginxConfig)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if e = atomicWrite(r.cfg.NginxConfig, []byte(content), 0600); e != nil {
		return nil, e
	}
	restore := func() {
		if len(old) > 0 {
			_ = atomicWrite(r.cfg.NginxConfig, old, 0600)
		} else {
			_ = os.Remove(r.cfg.NginxConfig)
		}
	}
	output, e := r.run(ctx, r.cfg.NginxBinary, "-t", "-c", r.cfg.NginxConfig)
	if e != nil {
		restore()
		return map[string]any{"saved": false, "applied": false, "output": output}, e
	}
	output, e = r.run(ctx, r.cfg.NginxBinary, "-s", "reload", "-c", r.cfg.NginxConfig)
	if e != nil {
		restore()
		return map[string]any{"applied": false, "output": output}, e
	}
	return map[string]any{"saved": true, "applied": true, "sha256": digest([]byte(content))}, nil
}

func (r *Runtime) scan(ctx context.Context) (map[string]any, error) {
	items := map[string]any{}
	for name, binary := range map[string]string{"nginx": r.cfg.NginxBinary} {
		p, e := exec.LookPath(binary)
		item := map[string]any{"installed": e == nil}
		if e == nil {
			item["path"] = p
		}
		items[name] = item
	}
	interfaces, e := net.Interfaces()
	if e != nil {
		return nil, e
	}
	addresses := []map[string]any{}
	for _, intf := range interfaces {
		addrs, e := intf.Addrs()
		if e != nil {
			continue
		}
		for _, a := range addrs {
			addresses = append(addresses, map[string]any{"interface": intf.Name, "address": a.String(), "up": intf.Flags&net.FlagUp != 0})
		}
	}
	return map[string]any{"services": items, "addresses": addresses, "core": r.status(ctx)}, nil
}

func latency(ctx context.Context, p map[string]any) (map[string]any, error) {
	target, _ := p["target"].(string)
	if _, _, e := net.SplitHostPort(target); e != nil {
		return nil, errors.New("target must be host:port")
	}
	count := 3
	if n, ok := p["count"].(float64); ok {
		count = int(n)
	}
	if count < 1 || count > 10 {
		return nil, errors.New("count must be 1..10")
	}
	samples := []map[string]any{}
	success := 0
	var total float64
	for i := 0; i < count; i++ {
		start := time.Now()
		conn, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", target)
		item := map[string]any{"success": e == nil}
		if e == nil {
			ms := float64(time.Since(start).Microseconds()) / 1000
			item["latency_ms"] = ms
			total += ms
			success++
			conn.Close()
		} else {
			item["error"] = e.Error()
		}
		samples = append(samples, item)
	}
	out := map[string]any{"target": target, "method": "tcp_connect", "samples": samples, "failure_percent": float64(count-success) * 100 / float64(count)}
	if success > 0 {
		out["average_ms"] = total / float64(success)
	}
	return out, nil
}
