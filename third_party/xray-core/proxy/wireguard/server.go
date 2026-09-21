package wireguard

import (
	"context"

	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

var nullDestination = net.TCPDestination(net.AnyIP, 0)

type Server struct {
	bindServer *netBindServer

	info          routingInfo
	policyManager policy.Manager
}

type routingInfo struct {
	ctx        context.Context
	dispatcher routing.Dispatcher
	inboundTag *session.Inbound
	contentTag *session.Content
}

func NewServer(ctx context.Context, conf *DeviceConfig) (*Server, error) {
	v := core.MustFromContext(ctx)

	endpoints, hasIPv4, hasIPv6, err := parseEndpoints(conf)
	if err != nil {
		return nil, err
	}

	server := &Server{
		bindServer: &netBindServer{
			netBind: netBind{
				dns: v.GetFeature(dns.ClientType()).(dns.Client),
				dnsOption: dns.IPOption{
					IPv4Enable: hasIPv4,
					IPv6Enable: hasIPv6,
				},
				workers:   int(conf.NumWorkers),
				readQueue: make(chan *netReadInfo),
			},
		},
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	tun, err := conf.createTun()(endpoints, int(conf.Mtu), server.forwardConnection)
	if err != nil {
		return nil, err
	}

	if err = tun.BuildDevice(createIPCRequest(conf), server.bindServer); err != nil {
		_ = tun.Close()
		return nil, err
	}

	return server, nil
}

func (*Server) Network() []net.Network {
	return []net.Network{net.Network_UDP}
}

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	s.info = routingInfo{
		ctx:        ctx,
		dispatcher: dispatcher,
		inboundTag: session.InboundFromContext(ctx),
		contentTag: session.ContentFromContext(ctx),
	}

	ep, err := s.bindServer.ParseEndpoint(conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	nep := ep.(*netEndpoint)
	nep.conn = conn

	reader := buf.NewPacketReader(conn)
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			nep.conn = nil
			buf.ReleaseMulti(mb)
			return err
		}

		for i, b := range mb {
			buff := b.Bytes()

			if b.Len() > 3 {
				buff[1] = 0
				buff[2] = 0
				buff[3] = 0
			}

			select {
			case s.bindServer.readQueue <- &netReadInfo{
				buff:     buff,
				endpoint: nep,
			}:
			case <-s.bindServer.closedCh:
				nep.conn = nil
				buf.ReleaseMulti(mb[i:])
				return errors.New("bind closed")
			}
		}
	}
}

func (s *Server) forwardConnection(dest net.Destination, conn net.Conn) {
	if s.info.dispatcher == nil {
		errors.LogError(s.info.ctx, "unexpected: dispatcher == nil")
		return
	}

	ctx, cancel := context.WithCancel(core.ToBackgroundDetachedContext(s.info.ctx))
	sid := session.NewID()
	ctx = c.ContextWithID(ctx, sid)
	inbound := session.Inbound{}
	if s.info.inboundTag != nil {
		inbound = *s.info.inboundTag
	}
	inbound.Name = "wireguard"
	inbound.CanSpliceCopy = 3

	inbound.Source = net.DestinationFromAddr(conn.RemoteAddr())
	ctx = session.ContextWithInbound(ctx, &inbound)
	content := new(session.Content)
	if s.info.contentTag != nil {
		content.SniffingRequest = s.info.contentTag.SniffingRequest
	}
	ctx = session.ContextWithContent(ctx, content)
	ctx = session.SubContextFromMuxInbound(ctx)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   nullDestination,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
	})

	err := s.info.dispatcher.DispatchLink(ctx, dest, &transport.Link{
		Reader: buf.NewReader(conn),
		Writer: buf.NewWriter(conn),
	})

	if err != nil {
		errors.LogInfoInner(ctx, err, "connection ends")
	}

	cancel()
	conn.Close()
}
