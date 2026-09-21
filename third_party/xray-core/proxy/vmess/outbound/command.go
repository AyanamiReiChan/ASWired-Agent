package outbound

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

func (h *Handler) handleCommand(dest net.Destination, cmd protocol.ResponseCommand) {
	switch cmd.(type) {
	default:
	}
}
