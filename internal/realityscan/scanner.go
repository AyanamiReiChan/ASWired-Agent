// Package realityscan performs bounded TLS feasibility checks from the Agent's network.
// Its result contract matches the controller's REALITY scanner.
package realityscan

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

func newID() string { return rand.Text() }

const realityScanLimit = 128

var realityScanDefaults = []string{"www.microsoft.com", "www.apple.com", "www.cloudflare.com", "www.amazon.com", "www.mozilla.org"}

type realityScanTarget struct {
	address string
	host    string
	port    int
	isIP    bool
}

type realityScanResult struct {
	ID                 string   `json:"id"`
	Target             string   `json:"target"`
	Host               string   `json:"host"`
	IP                 string   `json:"ip"`
	Port               int      `json:"port"`
	Feasible           bool     `json:"feasible"`
	TLS13              bool     `json:"tls13"`
	H2                 bool     `json:"h2"`
	X25519             bool     `json:"x25519"`
	CertValid          bool     `json:"certValid"`
	CertChainValid     bool     `json:"certChainValid"`
	CertChainBytes     int      `json:"certChainBytes"`
	ServerNames        []string `json:"serverNames"`
	ALPN               string   `json:"alpn"`
	TLSVersion         string   `json:"tlsVersion"`
	CurveID            uint16   `json:"curveID"`
	LatencyMS          float64  `json:"latencyMs"`
	TCPMS              float64  `json:"tcpMs"`
	HandshakeMS        float64  `json:"handshakeMs"`
	CertificateExpires string   `json:"certificateExpires"`
	CertSubject        string   `json:"certSubject"`
	CertIssuer         string   `json:"certIssuer"`
	Reason             string   `json:"reason"`
	CheckedAt          string   `json:"checkedAt"`
}

func parseRealityScanTarget(raw string) (realityScanTarget, error) {
	host, port := raw, 443
	if ip, e := netip.ParseAddr(raw); e == nil {
		if ip.Zone() != "" {
			return realityScanTarget{}, errors.New("不支持带区域标识的IP地址")
		}
		host = ip.Unmap().String()
	} else if strings.ContainsAny(raw, ":[]") {
		var portText string
		var err error
		host, portText, err = net.SplitHostPort(raw)
		if err != nil {
			return realityScanTarget{}, errors.New("端口格式无效，IPv6带端口时须使用[地址]:端口")
		}
		port, err = strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 || portText != strconv.Itoa(port) {
			return realityScanTarget{}, errors.New("端口须为1到65535的整数")
		}
	}
	isIP := false
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return realityScanTarget{}, errors.New("不支持带区域标识的IP地址")
		}
		host, isIP = ip.Unmap().String(), true
	} else {
		var err error
		host, err = realityDomain(host)
		if err != nil {
			return realityScanTarget{}, err
		}
	}
	return realityScanTarget{address: net.JoinHostPort(host, strconv.Itoa(port)), host: host, port: port, isIP: isIP}, nil
}

func parseRealityScanTargets(raw string) ([]realityScanTarget, error) {
	if len(raw) > 64<<10 {
		return nil, errors.New("扫描输入过长")
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(parts) == 0 {
		parts = realityScanDefaults
	}
	if len(parts) > realityScanLimit {
		return nil, errors.New("每次最多扫描128个目标")
	}
	targets := []realityScanTarget{}
	seen := map[string]bool{}
	expanded := 0
	appendTarget := func(raw string) error {
		expanded++
		if expanded > realityScanLimit {
			return errors.New("展开后超过128个目标，请缩小扫描范围")
		}
		target, err := parseRealityScanTarget(raw)
		if err != nil {
			return err
		}
		if !seen[target.address] {
			seen[target.address] = true
			targets = append(targets, target)
		}
		return nil
	}
	for _, part := range parts {
		if strings.Contains(part, "/") {
			prefix, err := netip.ParsePrefix(part)
			if err != nil || prefix.Addr().Is4In6() {
				return nil, errors.New("CIDR格式无效")
			}
			if prefix.Addr().BitLen()-prefix.Bits() > 7 {
				return nil, errors.New("每个CIDR最多包含128个地址，请使用更小的网段")
			}
			prefix = prefix.Masked()
			for addr := prefix.Addr(); addr.IsValid() && prefix.Contains(addr); addr = addr.Next() {
				if err := appendTarget(addr.String()); err != nil {
					return nil, err
				}
			}
		} else if err := appendTarget(part); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

func realityCertificateNames(cert *x509.Certificate) []string {
	names := []string{}
	seen := map[string]bool{}
	for _, raw := range cert.DNSNames {
		name, err := realityDomain(raw)
		if err == nil && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

func probeRealityConnection(ctx context.Context, target realityScanTarget, serverName string, dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) realityScanResult {
	result := realityScanResult{Target: target.address, Host: serverName, Port: target.port, ServerNames: []string{}, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	started := time.Now()
	conn, err := dial(ctx, "tcp", target.address)
	if err != nil {
		result.Reason = err.Error()
		result.LatencyMS = float64(time.Since(started).Microseconds()) / 1000
		return result
	}
	defer conn.Close()
	tcpDone := time.Now()
	result.IP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())
	result.TCPMS = float64(tcpDone.Sub(started).Microseconds()) / 1000
	secure := tls.Client(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true})
	err = secure.HandshakeContext(ctx)
	result.HandshakeMS = float64(time.Since(tcpDone).Microseconds()) / 1000
	result.LatencyMS = float64(time.Since(started).Microseconds()) / 1000
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	state := secure.ConnectionState()
	result.TLSVersion = tls.VersionName(state.Version)
	result.TLS13 = state.Version == tls.VersionTLS13
	result.ALPN = state.NegotiatedProtocol
	result.H2 = state.NegotiatedProtocol == "h2"
	result.CurveID = uint16(state.CurveID)
	result.X25519 = state.CurveID == tls.X25519
	reasons := []string{}
	if !result.TLS13 {
		reasons = append(reasons, "未协商TLS 1.3")
	}
	if !result.H2 {
		reasons = append(reasons, "未协商h2")
	}
	if !result.X25519 {
		reasons = append(reasons, "未协商X25519")
	}
	if len(state.PeerCertificates) == 0 {
		reasons = append(reasons, "目标未返回证书")
	} else {
		leaf := state.PeerCertificates[0]
		result.CertificateExpires = leaf.NotAfter.UTC().Format(time.RFC3339Nano)
		result.CertSubject, result.CertIssuer = leaf.Subject.String(), leaf.Issuer.String()
		result.ServerNames = realityCertificateNames(leaf)
		intermediates := x509.NewCertPool()
		for i, cert := range state.PeerCertificates {
			result.CertChainBytes += len(cert.Raw)
			if i > 0 {
				intermediates.AddCert(cert)
			}
		}
		_, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		result.CertChainValid = verifyErr == nil
		if verifyErr != nil {
			reasons = append(reasons, "证书信任链无效: "+verifyErr.Error())
		}
		if serverName != "" {
			hostErr := leaf.VerifyHostname(serverName)
			result.CertValid = result.CertChainValid && hostErr == nil
			if hostErr != nil {
				reasons = append(reasons, "证书域名不匹配: "+hostErr.Error())
			}
		} else {
			reasons = append(reasons, "IP目标需要确认可用SNI域名")
		}
	}
	result.Feasible = result.TLS13 && result.H2 && result.X25519 && result.CertValid
	result.Reason = strings.Join(reasons, "；")
	return result
}

func scanRealityTarget(ctx context.Context, target realityScanTarget, dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) realityScanResult {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	serverName := target.host
	if target.isIP {
		serverName = ""
	}
	result := probeRealityConnection(ctx, target, serverName, dial, roots)
	if target.isIP {
		for _, name := range result.ServerNames {
			if ctx.Err() != nil {
				break
			}
			confirmed := probeRealityConnection(ctx, target, name, dial, roots)
			if confirmed.Feasible {
				result = confirmed
				break
			}
		}
		if !result.Feasible {
			result.Host = ""
			result.Reason = "未在原IP确认可用SNI域名；" + result.Reason
		}
	}
	result.ID = newID()
	return result
}

func realityDomain(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	if len(domain) > 253 || len(domain) < 4 || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil || strings.HasSuffix(domain, ".") || strings.ContainsAny(domain, "/:@?#\\ \t\r\n*") {
		return "", errors.New("请填写完整域名，不含协议、端口、路径、IP或通配符")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("域名标签无效")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("域名须使用ASCII或Punycode")
			}
		}
	}
	return domain, nil
}
func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	if _, e = strconv.Atoi(port); e != nil {
		return nil, e
	}
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
	if e != nil {
		return nil, e
	}
	if len(ips) == 0 {
		return nil, errors.New("destination has no address")
	}
	for _, value := range ips {
		ip := value.IP
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("扫描不能请求私网、回环或链路本地地址")
		}
		for _, cidr := range []string{"0.0.0.0/8", "240.0.0.0/4", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
			_, reserved, _ := net.ParseCIDR(cidr)
			if reserved.Contains(ip) {
				return nil, errors.New("扫描不能请求保留地址")
			}
		}
	}
	var last error
	for _, ip := range ips {
		conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return conn, nil
		}
		last = e
	}
	return nil, fmt.Errorf("外部连接失败: %w", last)
}

func Scan(ctx context.Context, raw string) (map[string]any, error) {
	return scan(ctx, raw, publicDial, nil)
}

func scan(ctx context.Context, raw string, dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) (map[string]any, error) {
	targets, err := parseRealityScanTargets(raw)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 55*time.Second)
	defer cancel()
	results := make([]realityScanResult, len(targets))
	jobs := make(chan int, len(targets))
	for i := range targets {
		jobs <- i
	}
	close(jobs)
	var workers sync.WaitGroup
	for range min(16, len(targets)) {
		workers.Go(func() {
			for i := range jobs {
				if ctx.Err() != nil {
					return
				}
				results[i] = scanRealityTarget(ctx, targets[i], dial, roots)
			}
		})
	}
	workers.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	count := 0
	for _, result := range results {
		if result.Feasible {
			count++
		}
	}
	return map[string]any{"results": results, "total": len(results), "feasibleCount": count, "source": "agent"}, nil
}
