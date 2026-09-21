package internet

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/sagernet/sing/common/control"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

var effectiveListener = DefaultListener{}

type DefaultListener struct {
	controllers []control.Func
}

func getControlFunc(ctx context.Context, sockopt *SocketConfig, controllers []control.Func) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			for _, controller := range controllers {
				if err := controller(network, address, c); err != nil {
					errors.LogInfoInner(ctx, err, "failed to apply external controller")
				}
			}

			if sockopt != nil {
				if err := applyInboundSocketOptions(network, fd, sockopt); err != nil {
					errors.LogInfoInner(ctx, err, "failed to apply socket options to incoming connection")
				}
			}

			setReusePort(fd)
		})
	}
}

type UnixListenerWrapper struct {
	*net.UnixListener
	locker *FileLocker
}

func (l *UnixListenerWrapper) Accept() (net.Conn, error) {
	conn, err := l.UnixListener.Accept()
	if err != nil {
		return nil, err
	}
	return &UnixConnWrapper{UnixConn: conn.(*net.UnixConn)}, nil
}

func (l *UnixListenerWrapper) Close() error {
	if l.locker != nil {
		l.locker.Release()
		l.locker = nil
	}
	return l.UnixListener.Close()
}

type UnixConnWrapper struct {
	*net.UnixConn
}

func (conn *UnixConnWrapper) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP: []byte{0, 0, 0, 0},
	}
}

func (dl *DefaultListener) Listen(ctx context.Context, addr net.Addr, sockopt *SocketConfig) (l net.Listener, err error) {
	var lc net.ListenConfig
	var network, address string

	callback := func(l net.Listener, err error) (net.Listener, error) {
		return l, err
	}

	switch addr := addr.(type) {
	case *net.TCPAddr:
		network = addr.Network()
		address = addr.String()
		lc.Control = getControlFunc(ctx, sockopt, dl.controllers)

		lc.KeepAlive = -1
		if sockopt != nil {
			if sockopt.TcpKeepAliveIdle*sockopt.TcpKeepAliveInterval < 0 {
				return nil, errors.New("invalid TcpKeepAliveIdle or TcpKeepAliveInterval value: ", sockopt.TcpKeepAliveIdle, " ", sockopt.TcpKeepAliveInterval)
			}
			lc.KeepAliveConfig = net.KeepAliveConfig{
				Enable:   false,
				Idle:     -1,
				Interval: -1,
				Count:    -1,
			}
			if sockopt.TcpKeepAliveIdle > 0 {
				lc.KeepAliveConfig.Enable = true
				lc.KeepAliveConfig.Idle = time.Duration(sockopt.TcpKeepAliveIdle) * time.Second
			}
			if sockopt.TcpKeepAliveInterval > 0 {
				lc.KeepAliveConfig.Enable = true
				lc.KeepAliveConfig.Interval = time.Duration(sockopt.TcpKeepAliveInterval) * time.Second
			}
			if sockopt.TcpMptcp {
				lc.SetMultipathTCP(true)
			}
		}
	case *net.UnixAddr:
		lc.Control = nil
		network = addr.Network()
		address = addr.Name

		if (runtime.GOOS == "linux" || runtime.GOOS == "android") && address[0] == '@' {

			if len(address) > 1 && address[1] == '@' {

				fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path))
				copy(fullAddr, address[1:])
				address = string(fullAddr)
			}
		} else {

			var filePerm *os.FileMode
			if s := strings.Split(address, ","); len(s) == 2 {
				address = s[0]
				perm, perr := strconv.ParseUint(s[1], 8, 32)
				if perr != nil {
					return nil, errors.New("failed to parse permission: " + s[1]).Base(perr)
				}

				mode := os.FileMode(perm)
				filePerm = &mode
			}

			locker := &FileLocker{
				path: address + ".lock",
			}
			if err := locker.Acquire(); err != nil {
				return nil, err
			}

			callback = func(l net.Listener, err error) (net.Listener, error) {
				if err != nil {
					locker.Release()
					return nil, err
				}
				l = &UnixListenerWrapper{UnixListener: l.(*net.UnixListener), locker: locker}
				if filePerm == nil {
					return l, nil
				}
				err = os.Chmod(address, *filePerm)
				if err != nil {
					l.Close()
					return nil, errors.New("failed to set permission for " + address).Base(err)
				}
				return l, nil
			}
		}
	}

	l, err = callback(lc.Listen(ctx, network, address))
	if err == nil && sockopt != nil && sockopt.AcceptProxyProtocol {
		policyFunc := func(upstream net.Addr) (proxyproto.Policy, error) { return proxyproto.REQUIRE, nil }
		l = &proxyproto.Listener{Listener: l, Policy: policyFunc}
	}
	return l, err
}

func (dl *DefaultListener) ListenPacket(ctx context.Context, addr net.Addr, sockopt *SocketConfig) (net.PacketConn, error) {
	var lc net.ListenConfig

	lc.Control = getControlFunc(ctx, sockopt, dl.controllers)

	return lc.ListenPacket(ctx, addr.Network(), addr.String())
}

func RegisterListenerController(controller control.Func) error {
	if controller == nil {
		return errors.New("nil listener controller")
	}

	effectiveListener.controllers = append(effectiveListener.controllers, controller)
	return nil
}
