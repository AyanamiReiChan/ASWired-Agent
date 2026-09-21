package speedtest

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func sourceURL(value string) (*url.URL, error) {
	u, e := url.Parse(value)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("subscription source must be an HTTP(S) URL without embedded credentials")
	}
	return u, nil
}
func (r *Runner) fetchSource(ctx context.Context, p map[string]any) (map[string]any, error) {
	value, _ := p["url"].(string)
	u, e := sourceURL(value)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	allowed := func(candidate *url.URL) bool {
		if len(r.cfg.SourceAllowedOrigins) == 0 {
			return true
		}
		origin := candidate.Scheme + "://" + candidate.Host
		for _, v := range r.cfg.SourceAllowedOrigins {
			if origin == strings.TrimRight(v, "/") {
				return true
			}
		}
		return false
	}
	if !allowed(u) {
		return nil, errors.New("source origin is not in this Home client's configured allowlist")
	}
	transport := &http.Transport{DisableCompression: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		if e != nil {
			return nil, errors.New("source host resolution failed")
		}
		if len(ips) == 0 {
			return nil, errors.New("source host has no addresses")
		}
		for _, a := range ips {
			if !r.cfg.SourceAllowPrivate && (a.IP.IsPrivate() || a.IP.IsLoopback() || a.IP.IsLinkLocalUnicast() || a.IP.IsLinkLocalMulticast() || a.IP.IsMulticast() || a.IP.IsUnspecified()) {
				return nil, errors.New("source resolved to a private or special-use address")
			}
		}
		var last error
		for _, a := range ips {
			conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
			if e == nil {
				return conn, nil
			}
			last = e
		}
		return nil, last
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("too many source redirects")
		}
		if _, e := sourceURL(next.URL.String()); e != nil {
			return e
		}
		if !allowed(next.URL) {
			return errors.New("redirect origin is not allowed")
		}
		previous := via[len(via)-1]
		if previous.URL.Scheme == "https" && next.URL.Scheme == "http" {
			return errors.New("source redirect cannot downgrade HTTPS")
		}
		if !strings.EqualFold(previous.URL.Scheme+"://"+previous.URL.Host, next.URL.Scheme+"://"+next.URL.Host) {
			next.Header = make(http.Header)
		}
		return nil
	}}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return nil, e
	}
	if headers, ok := p["headers"].(map[string]any); ok {
		for key, value := range headers {
			switch http.CanonicalHeaderKey(key) {
			case "Authorization", "Accept", "User-Agent", "Cookie":
				s, ok := value.(string)
				if !ok || len(s) > 4096 || strings.ContainsAny(s, "\r\n") {
					return nil, errors.New("invalid source request header")
				}
				req.Header.Set(key, s)
			default:
				return nil, errors.New("unsupported source request header")
			}
		}
	}
	res, e := client.Do(req)
	if e != nil {
		return nil, errors.New("subscription source request failed")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, errors.New("subscription source returned HTTP " + strconv.Itoa(res.StatusCode))
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, (8<<20)+1))
	if e != nil {
		return nil, errors.New("subscription source read failed")
	}
	if len(b) > 8<<20 {
		return nil, errors.New("subscription source exceeds 8 MiB")
	}
	if !utf8.Valid(b) {
		return nil, errors.New("subscription source must contain UTF-8 text")
	}
	headers := map[string]string{}
	for _, name := range []string{"subscription-userinfo", "content-type", "profile-title", "profile-update-interval"} {
		if value := res.Header.Get(name); value != "" && len(value) < 8192 {
			headers[name] = value
		}
	}
	return map[string]any{"body_base64": base64.StdEncoding.EncodeToString(b), "status": res.StatusCode, "headers": headers, "final_url": res.Request.URL.String(), "bytes": len(b), "source": "home", "source_id": r.cfg.SourceID, "source_mode": r.cfg.SourceMode, "fetched_at": time.Now().Unix()}, nil
}
