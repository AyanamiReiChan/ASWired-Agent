package dispatcher

import (
	"context"

	"github.com/xtls/xray-core/common/aswired"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

// ConfigureProxyIPv4 is set once by the embedding Agent before the core starts.
// Its scope is the configured client inbounds, excluding Xray's own API inbound.
func (d *DefaultDispatcher) ConfigureProxyIPv4(tags []string) {
	d.proxyIPv4Inbounds = make(map[string]bool, len(tags))
	for _, tag := range tags {
		d.proxyIPv4Inbounds[tag] = true
	}
}

func (d *DefaultDispatcher) protectProxyIPv4(ctx context.Context, link *transport.Link) (context.Context, error) {
	outbounds := session.OutboundsFromContext(ctx)
	inbound := session.InboundFromContext(ctx)
	content := session.ContentFromContext(ctx)
	if len(outbounds) != 1 || inbound == nil || !d.proxyIPv4Inbounds[inbound.Tag] || (content != nil && content.SkipDNSResolve) {
		return ctx, nil
	}
	ctx = aswired.ContextWithProxyIPv4(ctx, d.proxyIPv4DNS)
	ob := outbounds[0]
	// Refuse literal IPv6 even when sniffing replaced it with a hostname.
	if ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address.Family().IsIPv6() {
		_, err := aswired.ProxyIPv4Destination(ctx, ob.OriginalTarget)
		return ctx, err
	}
	target, err := aswired.ProxyIPv4Destination(ctx, ob.Target)
	if err != nil {
		return ctx, err
	}
	ob.Target = target
	if ob.Target.Network == net.Network_UDP {
		link.Reader = &aswired.ProxyIPv4Reader{Reader: link.Reader, Context: ctx}
	}
	return ctx, nil
}
