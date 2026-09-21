package routing

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/transport"
)

type Dispatcher interface {
	features.Feature

	Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error)
	DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error
}

func DispatcherType() interface{} {
	return (*Dispatcher)(nil)
}
