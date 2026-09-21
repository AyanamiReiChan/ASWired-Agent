package mihomoapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

func AwaitConfiguration(ctx context.Context, address, secret string) error {
	host, _, err := net.SplitHostPort(address)
	ip, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || !ip.IsLoopback() || secret == "" {
		return errors.New("mihomo startup barrier requires a private loopback API")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://"+address+"/configs", strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("mihomo private API redirects are forbidden")
	}}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("mihomo configuration startup barrier failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return errors.New("mihomo configuration startup barrier did not complete")
	}
	return nil
}
