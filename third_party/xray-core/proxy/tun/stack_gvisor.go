package tun

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	defaultNIC tcpip.NICID = 1

	tcpRXBufMinSize = tcp.MinBufferSize
	tcpRXBufDefSize = tcp.DefaultSendBufferSize
	tcpRXBufMaxSize = 8 << 20

	tcpTXBufMinSize = tcp.MinBufferSize
	tcpTXBufDefSize = tcp.DefaultReceiveBufferSize
	tcpTXBufMaxSize = 6 << 20
)

type stackGVisor struct {
	ctx         context.Context
	tun         GVisorTun
	idleTimeout time.Duration
	handler     *Handler
	stack       *stack.Stack
	endpoint    stack.LinkEndpoint
}

type GVisorTun interface {
	newEndpoint() (stack.LinkEndpoint, error)
}

func NewStack(ctx context.Context, options StackOptions, handler *Handler) (Stack, error) {
	gStack := &stackGVisor{
		ctx:         ctx,
		tun:         options.Tun.(GVisorTun),
		idleTimeout: options.IdleTimeout,
		handler:     handler,
	}

	return gStack, nil
}

func (t *stackGVisor) Start() error {
	linkEndpoint, err := t.tun.newEndpoint()
	if err != nil {
		return err
	}

	ipStack, err := createStack(linkEndpoint)
	if err != nil {
		return err
	}

	tcpForwarder := tcp.NewForwarder(ipStack, 0, 65535, func(r *tcp.ForwarderRequest) {
		go func(r *tcp.ForwarderRequest) {
			var wq waiter.Queue
			var id = r.ID()

			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				errors.LogError(t.ctx, err.String())
				r.Complete(true)
				return
			}

			options := ep.SocketOptions()
			options.SetKeepAlive(false)
			options.SetReuseAddress(true)
			options.SetReusePort(true)

			t.handler.HandleConnection(
				gonet.NewTCPConn(&wq, ep),

				net.TCPDestination(net.IPAddress(id.LocalAddress.AsSlice()), net.Port(id.LocalPort)),
			)

			ep.Close()

			r.Complete(false)
		}(r)
	})
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := newUdpConnectionHandler(t.handler.HandleConnection, t.writeRawUDPPacket)
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		data := pkt.Data().AsRange().ToSlice()
		if len(data) == 0 {
			return false
		}

		src := net.UDPDestination(net.IPAddress(id.RemoteAddress.AsSlice()), net.Port(id.RemotePort))
		dst := net.UDPDestination(net.IPAddress(id.LocalAddress.AsSlice()), net.Port(id.LocalPort))

		return udpForwarder.HandlePacket(src, dst, data)
	})

	t.stack = ipStack
	t.endpoint = linkEndpoint

	return nil
}

func (t *stackGVisor) writeRawUDPPacket(payload []byte, src net.Destination, dst net.Destination) error {
	udpLen := header.UDPMinimumSize + len(payload)
	srcIP := tcpip.AddrFromSlice(src.Address.IP())
	dstIP := tcpip.AddrFromSlice(dst.Address.IP())

	isIPv4 := dst.Address.Family().IsIPv4()
	ipHdrSize := header.IPv6MinimumSize
	ipProtocol := header.IPv6ProtocolNumber
	if isIPv4 {
		ipHdrSize = header.IPv4MinimumSize
		ipProtocol = header.IPv4ProtocolNumber
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: ipHdrSize + header.UDPMinimumSize,
		Payload:            buffer.MakeWithData(payload),
	})
	defer pkt.DecRef()

	udpHdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udpHdr.Encode(&header.UDPFields{
		SrcPort: uint16(src.Port),
		DstPort: uint16(dst.Port),
		Length:  uint16(udpLen),
	})

	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcIP, dstIP, uint16(udpLen))
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(payload, xsum)))

	if isIPv4 {
		ipHdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(header.IPv4MinimumSize + udpLen),
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     srcIP,
			DstAddr:     dstIP,
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	} else {
		ipHdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
		ipHdr.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(udpLen),
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           srcIP,
			DstAddr:           dstIP,
		})
	}

	err := t.stack.WriteRawPacket(defaultNIC, ipProtocol, buffer.MakeWithView(pkt.ToView()))
	if err != nil {
		return errors.New("failed to write raw udp packet back to stack", err)
	}

	return nil
}

func (t *stackGVisor) Close() error {
	if t.stack == nil {
		return nil
	}
	t.endpoint.Attach(nil)
	t.stack.Close()
	for _, endpoint := range t.stack.CleanupEndpoints() {
		endpoint.Abort()
	}

	return nil
}

func createStack(ep stack.LinkEndpoint) (*stack.Stack, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	}
	gStack := stack.New(opts)

	err := gStack.CreateNIC(defaultNIC, ep)
	if err != nil {
		return nil, errors.New(err.String())
	}

	gStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: defaultNIC},
		{Destination: header.IPv6EmptySubnet, NIC: defaultNIC},
	})

	err = gStack.SetSpoofing(defaultNIC, true)
	if err != nil {
		return nil, errors.New(err.String())
	}
	err = gStack.SetPromiscuousMode(defaultNIC, true)
	if err != nil {
		return nil, errors.New(err.String())
	}

	cOpt := tcpip.CongestionControlOption("cubic")
	gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &cOpt)
	sOpt := tcpip.TCPSACKEnabled(true)
	gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)

	rOpt := tcpip.TCPRecovery(0)
	gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &rOpt)

	tcpRXBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcpRXBufMinSize,
		Default: tcpRXBufDefSize,
		Max:     tcpRXBufMaxSize,
	}
	err = gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRXBufOpt)
	if err != nil {
		return nil, errors.New(err.String())
	}

	tcpTXBufOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcpTXBufMinSize,
		Default: tcpTXBufDefSize,
		Max:     tcpTXBufMaxSize,
	}
	err = gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTXBufOpt)
	if err != nil {
		return nil, errors.New(err.String())
	}

	return gStack, nil
}
