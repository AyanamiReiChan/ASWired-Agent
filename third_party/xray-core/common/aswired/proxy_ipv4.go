package aswired

import (
	"context"
	"errors"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
)

type proxyIPv4Key struct{}

// ContextWithProxyIPv4 scopes the policy to the client destination. Nested
// outbound dispatches carry relay endpoints and intentionally remain unchanged.
func ContextWithProxyIPv4(ctx context.Context, client dns.Client) context.Context {
	return context.WithValue(ctx, proxyIPv4Key{}, client)
}

func ProxyIPv4Enabled(ctx context.Context) bool {
	return ctx != nil && ctx.Value(proxyIPv4Key{}) != nil && len(session.OutboundsFromContext(ctx)) == 1
}

func ProxyIPv4Destination(ctx context.Context, destination net.Destination) (net.Destination, error) {
	if !ProxyIPv4Enabled(ctx) {
		return destination, nil
	}
	if destination.Address == nil {
		return destination, errors.New("ASWired: missing proxy destination")
	}
	if destination.Address.Family().IsIPv6() {
		return destination, errors.New("ASWired: IPv6 proxy destinations are disabled")
	}
	if destination.Address.Family().IsDomain() {
		client := ctx.Value(proxyIPv4Key{}).(dns.Client)
		ips, _, err := client.LookupIP(destination.Address.Domain(), dns.IPOption{IPv4Enable: true})
		if err != nil {
			return destination, errors.New("ASWired: proxy destination has no usable IPv4 address")
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				destination.Address = net.IPAddress(v4)
				return destination, nil
			}
		}
		return destination, errors.New("ASWired: proxy destination has no usable IPv4 address")
	}
	return destination, nil
}

// UDP sessions can carry subsequent packet destinations without another routing
// dispatch. Check those destinations as well as the session's initial target.
type ProxyIPv4Reader struct {
	Reader  buf.Reader
	Context context.Context
}

func (r *ProxyIPv4Reader) Interrupt() { common.Interrupt(r.Reader) }

func (r *ProxyIPv4Reader) Close() error { return common.Close(r.Reader) }

func (r *ProxyIPv4Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	for _, b := range mb {
		if b != nil && b.UDP != nil {
			destination, failure := ProxyIPv4Destination(r.Context, *b.UDP)
			if failure != nil {
				buf.ReleaseMulti(mb)
				return nil, failure
			}
			copy := destination
			b.UDP = &copy
		}
	}
	return mb, err
}
