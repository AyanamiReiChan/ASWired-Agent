package realityscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type realityScanTLSFixture struct {
	dial      func(context.Context, string, string) (net.Conn, error)
	roots     *x509.CertPool
	mu        sync.Mutex
	addresses []string
	names     []string
}

func newRealityScanTLSFixture(t *testing.T, domains []string, alpn []string, version uint16, curves []tls.CurveID, expired bool, rejectSNI bool) *realityScanTLSFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	if expired {
		expires = time.Now().Add(-time.Minute)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "Fixture leaf"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expires, DNSNames: domains, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &realityScanTLSFixture{roots: x509.NewCertPool()}
	fixture.roots.AddCert(parsed)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12, MaxVersion: version, NextProtos: alpn, CurvePreferences: curves}
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		fixture.mu.Lock()
		fixture.names = append(fixture.names, hello.ServerName)
		fixture.mu.Unlock()
		if rejectSNI && hello.ServerName != "" {
			return nil, errors.New("SNI is not served at this IP")
		}
		return nil, nil
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = tls.Server(conn, cfg).HandshakeContext(ctx)
			}()
		}
	}()
	fixture.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		fixture.mu.Lock()
		fixture.addresses = append(fixture.addresses, address)
		fixture.mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}
	return fixture
}

func TestAgentRealityScanTLSAndIPSNI(t *testing.T) {
	for _, raw := range []string{"example.test", "1.1.1.1:443"} {
		fixture := newRealityScanTLSFixture(t, []string{"example.test"}, []string{"h2"}, tls.VersionTLS13, []tls.CurveID{tls.X25519}, false, false)
		data, err := scan(context.Background(), raw, fixture.dial, fixture.roots)
		if err != nil {
			t.Fatal(err)
		}
		results := data["results"].([]realityScanResult)
		if len(results) != 1 || !results[0].Feasible || results[0].Host != "example.test" || results[0].CheckedAt == "" {
			t.Fatalf("scan: %+v", data)
		}
		if strings.HasPrefix(raw, "1.") {
			fixture.mu.Lock()
			if len(fixture.addresses) != 2 || fixture.addresses[0] != "1.1.1.1:443" || fixture.addresses[1] != "1.1.1.1:443" || len(fixture.names) != 2 || fixture.names[1] != "example.test" {
				t.Errorf("SNI verification changed destination: %v %v", fixture.addresses, fixture.names)
			}
			fixture.mu.Unlock()
		}
	}
}
func TestAgentRealityRejectsInvalidTLSAndPrivateAddresses(t *testing.T) {
	for _, tc := range []struct {
		alpn    []string
		expired bool
		version uint16
	}{{[]string{"http/1.1"}, false, tls.VersionTLS13}, {[]string{"h2"}, true, tls.VersionTLS13}, {[]string{"h2"}, false, tls.VersionTLS12}} {
		fixture := newRealityScanTLSFixture(t, []string{"example.test"}, tc.alpn, tc.version, []tls.CurveID{tls.X25519}, tc.expired, false)
		data, err := scan(context.Background(), "example.test", fixture.dial, fixture.roots)
		if err != nil {
			t.Fatal(err)
		}
		if data["feasibleCount"].(int) != 0 {
			t.Fatal("accepted invalid TLS", data)
		}
	}
	for _, address := range []string{"127.0.0.1:443", "10.0.0.1:443", "169.254.169.254:80", "[::1]:443", "[fc00::1]:443"} {
		if conn, err := publicDial(context.Background(), "tcp", address); err == nil {
			conn.Close()
			t.Fatal("dialed private", address)
		}
	}
	if _, err := parseRealityScanTargets("1.1.1.0/24"); err == nil {
		t.Fatal("accepted oversized scan")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scan(ctx, "example.test", func(context.Context, string, string) (net.Conn, error) {
		t.Error("dial after cancellation")
		return nil, errors.New("unexpected")
	}, nil); err == nil {
		t.Fatal("accepted canceled scan")
	}
}
