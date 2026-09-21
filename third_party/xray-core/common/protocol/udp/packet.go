package udp

import (
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

type Packet struct {
	Payload *buf.Buffer
	Source  net.Destination
	Target  net.Destination
}
