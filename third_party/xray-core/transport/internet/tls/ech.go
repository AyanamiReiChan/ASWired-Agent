package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/crypto"
	dns2 "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/http2"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/crypto/cryptobyte"
)

func ApplyECH(c *Config, config *tls.Config) error {
	var ECHConfig []byte
	var err error

	var nameToQuery string
	if net.ParseAddress(config.ServerName).Family().IsDomain() {
		nameToQuery = config.ServerName
	}
	var DNSServer string

	if len(c.EchServerKeys) != 0 {
		KeySets, err := ConvertToGoECHKeys(c.EchServerKeys)
		if err != nil {
			return errors.New("Failed to unmarshal ECHKeySetList: ", err)
		}
		config.EncryptedClientHelloKeys = KeySets
	}

	if len(c.EchConfigList) != 0 {
		ECHForceQuery := c.EchForceQuery
		switch ECHForceQuery {
		case "none", "half", "full":
		case "":
			ECHForceQuery = "full"
		default:
			panic("Invalid ECHForceQuery: " + c.EchForceQuery)
		}
		defer func() {

			if err != nil || len(ECHConfig) == 0 {
				if ECHForceQuery == "full" {
					ECHConfig = []byte{1, 1, 4, 5, 1, 4}
				}
			}
			config.EncryptedClientHelloConfigList = ECHConfig
		}()

		if strings.Contains(c.EchConfigList, "://") {

			parts := strings.Split(c.EchConfigList, "+")
			if len(parts) == 2 {

				nameToQuery = parts[0]
				DNSServer = parts[1]
			} else if len(parts) == 1 {

				DNSServer = parts[0]
			} else {
				return errors.New("Invalid ECH DNS server format: ", c.EchConfigList)
			}
			if nameToQuery == "" {
				return errors.New("Using DNS for ECH Config needs serverName or use Server format example.com+https://1.1.1.1/dns-query")
			}
			ECHConfig, err = QueryRecord(nameToQuery, DNSServer, c.EchForceQuery, c.EchSocketSettings)
			if err != nil {
				return errors.New("Failed to query ECH DNS record for domain: ", nameToQuery, " at server: ", DNSServer).Base(err)
			}
		} else {
			ECHConfig, err = base64.StdEncoding.DecodeString(c.EchConfigList)
			if err != nil {
				return errors.New("Failed to unmarshal ECHConfigList: ", err)
			}
		}
	}

	return nil
}

type ECHConfigCache struct {
	configRecord atomic.Pointer[echConfigRecord]

	UpdateLock sync.Mutex
}

type echConfigRecord struct {
	config []byte
	expire time.Time
	err    error
}

var (
	GlobalECHConfigCache = utils.NewTypedSyncMap[string, *ECHConfigCache]()
	clientForECHDOH      = utils.NewTypedSyncMap[string, *http.Client]()
)

func ECHCacheKey(server, domain string, sockopt *internet.SocketConfig) string {
	return server + "|" + domain + "|" + fmt.Sprintf("%p", sockopt)
}

func (c *ECHConfigCache) Update(domain string, server string, isLockedUpdate bool, forceQuery string, sockopt *internet.SocketConfig) ([]byte, error) {
	if !isLockedUpdate {
		c.UpdateLock.Lock()
		defer c.UpdateLock.Unlock()
	}

	configRecord := c.configRecord.Load()
	if configRecord.expire.After(time.Now()) && configRecord.err == nil {
		errors.LogDebug(context.Background(), "Cache hit for domain after double check: ", domain)
		return configRecord.config, configRecord.err
	}

	errors.LogDebug(context.Background(), "Trying to query ECH config for domain: ", domain, " with ECH server: ", server)
	echConfig, ttl, err := dnsQuery(server, domain, sockopt)

	if err != nil && forceQuery == "full" {
		return nil, err
	}
	if ttl == 0 {
		ttl = dns2.DefaultTTL
	}
	configRecord = &echConfigRecord{
		config: echConfig,
		expire: time.Now().Add(time.Duration(ttl) * time.Second),
		err:    err,
	}
	c.configRecord.Store(configRecord)
	return configRecord.config, configRecord.err
}

func QueryRecord(domain string, server string, forceQuery string, sockopt *internet.SocketConfig) ([]byte, error) {
	GlobalECHConfigCacheKey := ECHCacheKey(server, domain, sockopt)
	echConfigCache, ok := GlobalECHConfigCache.Load(GlobalECHConfigCacheKey)
	if !ok {
		echConfigCache = &ECHConfigCache{}
		echConfigCache.configRecord.Store(&echConfigRecord{})
		echConfigCache, _ = GlobalECHConfigCache.LoadOrStore(GlobalECHConfigCacheKey, echConfigCache)
	}
	configRecord := echConfigCache.configRecord.Load()
	if configRecord.expire.After(time.Now()) && (configRecord.err == nil || forceQuery == "none") {
		errors.LogDebug(context.Background(), "Cache hit for domain: ", domain)
		return configRecord.config, configRecord.err
	}

	if configRecord.expire == (time.Time{}) || configRecord.expire.Add(time.Hour*4).Before(time.Now()) {
		return echConfigCache.Update(domain, server, false, forceQuery, sockopt)
	} else {

		if echConfigCache.UpdateLock.TryLock() {
			go func() {
				defer echConfigCache.UpdateLock.Unlock()
				echConfigCache.Update(domain, server, true, forceQuery, sockopt)
			}()
		}
		return configRecord.config, configRecord.err
	}
}

func dnsQuery(server string, domain string, sockopt *internet.SocketConfig) ([]byte, uint32, error) {
	m := new(dns.Msg)
	var dnsResolve []byte
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	if strings.HasPrefix(server, "https://") || strings.HasPrefix(server, "h2c://") {
		h2c := strings.HasPrefix(server, "h2c://")
		m.SetEdns0(4096, false)
		padding := &dns.EDNS0_PADDING{Padding: make([]byte, int(crypto.RandBetween(100, 300)))}
		if opt := m.IsEdns0(); opt != nil {
			opt.Option = append(opt.Option, padding)
		}

		m.Id = 0
		msg, err := m.Pack()
		if err != nil {
			return nil, 0, err
		}
		var client *http.Client
		serverKey := ECHCacheKey(server, "", sockopt)
		if client, _ = clientForECHDOH.Load(serverKey); client == nil {

			tr := &http2.Transport{
				IdleConnTimeout: net.ConnIdleTimeout,
				ReadIdleTimeout: net.ChromeH2KeepAlivePeriod,
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					dest, err := net.ParseDestination(network + ":" + addr)
					if err != nil {
						return nil, err
					}
					var conn net.Conn

					conn, err = internet.DialSystem(ctx, dest, sockopt)
					if err != nil {
						return nil, err
					}

					if !h2c {
						u, err := url.Parse(server)
						if err != nil {
							return nil, err
						}
						conn = utls.UClient(conn, &utls.Config{ServerName: u.Hostname()}, utls.HelloChrome_Auto)
						if err := conn.(*utls.UConn).HandshakeContext(ctx); err != nil {
							return nil, err
						}
					}
					return conn, nil
				},
			}
			c := &http.Client{
				Timeout:   30 * time.Second,
				Transport: tr,
			}
			client, _ = clientForECHDOH.LoadOrStore(serverKey, c)
		}
		req, err := http.NewRequest("POST", server, bytes.NewReader(msg))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Accept", "application/dns-message")
		req.Header.Set("Content-Type", "application/dns-message")
		utils.TryDefaultHeadersWith(req.Header, "fetch")
		req.Header.Set("X-Padding", utils.H2Base62Pad(crypto.RandBetween(100, 1000)))

		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, 0, errors.New("query failed with response code:", resp.StatusCode)
		}
		dnsResolve = respBody
	} else if strings.HasPrefix(server, "udp://") {
		udpServerAddr := server[len("udp://"):]

		if !strings.Contains(udpServerAddr, ":") {
			udpServerAddr = udpServerAddr + ":53"
		}
		dest, err := net.ParseDestination("udp" + ":" + udpServerAddr)
		if err != nil {
			return nil, 0, errors.New("failed to parse udp dns server ", udpServerAddr, " for ECH: ", err)
		}
		dnsTimeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := internet.DialSystem(dnsTimeoutCtx, dest, sockopt)
		if err != nil {
			return nil, 0, err
		}
		defer func() {
			err := conn.Close()
			if err != nil {
				errors.LogDebug(context.Background(), "Failed to close connection: ", err)
			}
		}()
		msg, err := m.Pack()
		if err != nil {
			return nil, 0, err
		}
		conn.Write(msg)
		udpResponse := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Read(udpResponse)
		if err != nil {
			return nil, 0, err
		}
		dnsResolve = udpResponse
	}
	respMsg := new(dns.Msg)
	err := respMsg.Unpack(dnsResolve)
	if err != nil {
		return nil, 0, errors.New("failed to unpack dns response for ECH: ", err)
	}
	if len(respMsg.Answer) > 0 {
		for _, answer := range respMsg.Answer {
			if https, ok := answer.(*dns.HTTPS); ok && https.Hdr.Name == dns.Fqdn(domain) {
				for _, v := range https.Value {
					if echConfig, ok := v.(*dns.SVCBECHConfig); ok {
						errors.LogDebug(context.Background(), "Get ECH config:", echConfig.String(), " TTL:", respMsg.Answer[0].Header().Ttl)
						return echConfig.ECH, answer.Header().Ttl, nil
					}
				}
			}
		}
	}

	return nil, dns2.DefaultTTL, nil
}

var ErrInvalidLen = errors.New("goech: invalid length")

func ConvertToGoECHKeys(data []byte) ([]tls.EncryptedClientHelloKey, error) {
	var keys []tls.EncryptedClientHelloKey
	s := cryptobyte.String(data)
	for !s.Empty() {
		if len(s) < 2 {
			return keys, ErrInvalidLen
		}
		keyLength := int(binary.BigEndian.Uint16(s[:2]))
		if len(s) < keyLength+4 {
			return keys, ErrInvalidLen
		}
		configLength := int(binary.BigEndian.Uint16(s[keyLength+2 : keyLength+4]))
		if len(s) < 2+keyLength+2+configLength {
			return keys, ErrInvalidLen
		}
		child := cryptobyte.String(s[:2+keyLength+2+configLength])
		var (
			sk, config cryptobyte.String
		)
		if !child.ReadUint16LengthPrefixed(&sk) || !child.ReadUint16LengthPrefixed(&config) || !child.Empty() {
			return keys, ErrInvalidLen
		}
		if !s.Skip(2 + keyLength + 2 + configLength) {
			return keys, ErrInvalidLen
		}
		keys = append(keys, tls.EncryptedClientHelloKey{
			Config:     config,
			PrivateKey: sk,
		})
	}
	return keys, nil
}
