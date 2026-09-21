package session

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
)

type Context struct {
	Inbound  *session.Inbound
	Outbound *session.Outbound
	Content  *session.Content
}

func (ctx *Context) GetInboundTag() string {
	if ctx.Inbound == nil {
		return ""
	}
	return ctx.Inbound.Tag
}

func (ctx *Context) GetSourceIPs() []net.IP {
	if ctx.Inbound == nil || !ctx.Inbound.Source.IsValid() {
		return nil
	}

	if ctx.Inbound.Source.Address.Family().IsIP() {
		return []net.IP{ctx.Inbound.Source.Address.IP()}
	}

	return nil

}

func (ctx *Context) GetSourcePort() net.Port {
	if ctx.Inbound == nil || !ctx.Inbound.Source.IsValid() {
		return 0
	}
	return ctx.Inbound.Source.Port
}

func (ctx *Context) GetTargetIPs() []net.IP {
	if ctx.Outbound == nil || !ctx.Outbound.Target.IsValid() {
		return nil
	}

	if ctx.Outbound.Target.Address.Family().IsIP() {
		return []net.IP{ctx.Outbound.Target.Address.IP()}
	}

	return nil
}

func (ctx *Context) GetTargetPort() net.Port {
	if ctx.Outbound == nil || !ctx.Outbound.Target.IsValid() {
		return 0
	}
	return ctx.Outbound.Target.Port
}

func (ctx *Context) GetLocalIPs() []net.IP {
	if ctx.Inbound == nil || !ctx.Inbound.Local.IsValid() {
		return nil
	}

	if ctx.Inbound.Local.Address.Family().IsIP() {
		return []net.IP{ctx.Inbound.Local.Address.IP()}
	}

	return nil
}

func (ctx *Context) GetLocalPort() net.Port {
	if ctx.Inbound == nil || !ctx.Inbound.Local.IsValid() {
		return 0
	}
	return ctx.Inbound.Local.Port
}

func (ctx *Context) GetTargetDomain() string {
	if ctx.Outbound == nil || !ctx.Outbound.Target.IsValid() {
		return ""
	}
	dest := ctx.Outbound.RouteTarget
	if dest.IsValid() && dest.Address.Family().IsDomain() {
		return dest.Address.Domain()
	}

	dest = ctx.Outbound.Target
	if !dest.Address.Family().IsDomain() {
		return ""
	}
	return dest.Address.Domain()
}

func (ctx *Context) GetNetwork() net.Network {
	if ctx.Outbound == nil {
		return net.Network_Unknown
	}
	return ctx.Outbound.Target.Network
}

func (ctx *Context) GetProtocol() string {
	if ctx.Content == nil {
		return ""
	}
	return ctx.Content.Protocol
}

func (ctx *Context) GetUser() string {
	if ctx.Inbound == nil || ctx.Inbound.User == nil {
		return ""
	}
	return ctx.Inbound.User.Email
}

func (ctx *Context) GetVlessRoute() net.Port {
	if ctx.Inbound == nil {
		return 0
	}
	return ctx.Inbound.VlessRoute
}

func (ctx *Context) GetAttributes() map[string]string {
	if ctx.Content == nil {
		return nil
	}
	return ctx.Content.Attributes
}

func (ctx *Context) GetSkipDNSResolve() bool {
	if ctx.Content == nil {
		return false
	}
	return ctx.Content.SkipDNSResolve
}

func AsRoutingContext(ctx context.Context) routing.Context {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	return &Context{
		Inbound:  session.InboundFromContext(ctx),
		Outbound: ob,
		Content:  session.ContentFromContext(ctx),
	}
}
