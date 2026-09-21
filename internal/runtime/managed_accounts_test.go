package runtime

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"golang.org/x/net/proxy"
)

func TestManagedAccountsAuthenticateRotateAndRevoke(t *testing.T) {
	for _, kind := range []string{"socks", "http"} {
		t.Run(kind, func(t *testing.T) {
			r := newTestRuntime(t)
			port := freePort(t)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "managed-account") }))
			defer target.Close()
			settings := map[string]any{"accounts": []any{map[string]any{"user": "member.inbound", "pass": "first"}}, "userLevel": 0}
			if kind == "socks" {
				settings["auth"] = "password"
			}
			cfg := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"tag": "managed", "listen": "127.0.0.1", "port": port, "protocol": kind, "settings": settings}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
			command(t, r, "core.config.apply", map[string]any{"config": cfg, "auxiliary": map[string]any{"listeners": []any{}}})
			request := func(password string) bool {
				transport := &http.Transport{DisableKeepAlives: true}
				defer transport.CloseIdleConnections()
				address := net.JoinHostPort("127.0.0.1", fmtInt(port))
				if kind == "socks" {
					var auth *proxy.Auth
					if password != "" {
						auth = &proxy.Auth{User: "member.inbound", Password: password}
					}
					dialer, err := proxy.SOCKS5("tcp", address, auth, &net.Dialer{Timeout: time.Second})
					if err != nil {
						t.Fatal(err)
					}
					transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
						return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
					}
				} else {
					u := &url.URL{Scheme: "http", Host: address}
					if password != "" {
						u.User = url.UserPassword("member.inbound", password)
					}
					transport.Proxy = http.ProxyURL(u)
				}
				client := http.Client{Transport: transport, Timeout: 2 * time.Second}
				res, err := client.Get(target.URL)
				if err != nil {
					return false
				}
				defer res.Body.Close()
				body, _ := io.ReadAll(res.Body)
				return res.StatusCode == 200 && string(body) == "managed-account"
			}
			if !request("first") || request("") {
				t.Fatal("initial authentication failed")
			}
			command(t, r, "core.users.sync", map[string]any{"inbound": "managed", "users": []any{map[string]any{"email": "member.inbound", "password": "second"}}})
			if request("first") || !request("second") {
				t.Fatal("rotation failed")
			}
			command(t, r, "core.users.sync", map[string]any{"inbound": "managed", "users": []any{}})
			command(t, r, "core.restart", nil)
			if request("second") || request("") {
				t.Fatal("revocation opened anonymous access")
			}
			bad := r.Handle(context.Background(), wire.Command{Action: "core.config.apply", Params: map[string]any{"config": cfg, "auxiliary": map[string]any{"listeners": []any{map[string]any{"type": "anytls"}}}}})
			if bad.Status != "failed" || request("first") {
				t.Fatal("missing auxiliary core changed active credentials")
			}
		})
	}
}
