package udp

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
)

func PickPort() net.Port {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.LocalHostIP.IP(),
		Port: 0,
	})
	common.Must(err)
	defer conn.Close()

	addr := conn.LocalAddr().(*net.UDPAddr)
	return net.Port(addr.Port)
}
