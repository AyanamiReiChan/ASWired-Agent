package tcp

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
)

func PickPort() net.Port {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	common.Must(err)
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return net.Port(addr.Port)
}
