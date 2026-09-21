package routing

import (
	"github.com/xtls/xray-core/common/net"
)

type Context interface {
	GetInboundTag() string

	GetSourceIPs() []net.IP

	GetSourcePort() net.Port

	GetTargetIPs() []net.IP

	GetTargetPort() net.Port

	GetLocalIPs() []net.IP

	GetLocalPort() net.Port

	GetTargetDomain() string

	GetNetwork() net.Network

	GetProtocol() string

	GetUser() string

	GetVlessRoute() net.Port

	GetAttributes() map[string]string

	GetSkipDNSResolve() bool
}
