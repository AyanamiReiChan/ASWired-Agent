package tls

import (
	"context"
	gotls "crypto/tls"
	"net"
	"net/url"
	"strconv"

	utls "github.com/refraction-networking/utls"
	"google.golang.org/grpc/credentials"
)

type grpcUtlsInfo struct {
	State utls.ConnectionState
	credentials.CommonAuthInfo

	SPIFFEID *url.URL
}

func (t grpcUtlsInfo) AuthType() string {
	return "utls"
}

func (t grpcUtlsInfo) GetSecurityValue() credentials.ChannelzSecurityValue {
	v := &credentials.TLSChannelzSecurityValue{
		StandardName: "0x" + strconv.FormatUint(uint64(t.State.CipherSuite), 16),
	}

	if len(t.State.PeerCertificates) > 0 {
		v.RemoteCertificate = t.State.PeerCertificates[0].Raw
	}
	return v
}

type grpcUtls struct {
	config      *gotls.Config
	fingerprint *utls.ClientHelloID
}

func (c grpcUtls) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2",
		ServerName:       c.config.ServerName,
	}
}

func (c *grpcUtls) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (_ net.Conn, _ credentials.AuthInfo, err error) {

	cfg := c.config.Clone()
	if cfg.ServerName == "" {
		serverName, _, err := net.SplitHostPort(authority)
		if err != nil {

			serverName = authority
		}
		cfg.ServerName = serverName
	}
	conn := UClient(rawConn, cfg, c.fingerprint).(*UConn)
	errChannel := make(chan error, 1)
	go func() {
		errChannel <- conn.HandshakeContext(ctx)
		close(errChannel)
	}()
	select {
	case err := <-errChannel:
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
	case <-ctx.Done():
		conn.Close()
		return nil, nil, ctx.Err()
	}
	tlsInfo := grpcUtlsInfo{
		State: conn.ConnectionState(),
		CommonAuthInfo: credentials.CommonAuthInfo{
			SecurityLevel: credentials.PrivacyAndIntegrity,
		},
	}
	return conn, tlsInfo, nil
}

func (c *grpcUtls) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	panic("not available!")
}

func (c *grpcUtls) Clone() credentials.TransportCredentials {
	return NewGrpcUtls(c.config, c.fingerprint)
}

func (c *grpcUtls) OverrideServerName(serverNameOverride string) error {
	c.config.ServerName = serverNameOverride
	return nil
}

func NewGrpcUtls(c *gotls.Config, fingerprint *utls.ClientHelloID) credentials.TransportCredentials {
	tc := &grpcUtls{c.Clone(), fingerprint}
	return tc
}
