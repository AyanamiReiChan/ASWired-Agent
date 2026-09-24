package session

import (
	"context"
	"math/rand"
	"sync/atomic"

	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal"
)

func NewID() c.ID {
	for {
		id := c.ID(rand.Uint32())
		if id != 0 {
			return id
		}
	}
}

func ExportIDToError(ctx context.Context) errors.ExportOption {
	id := c.IDFromContext(ctx)
	return func(h *errors.ExportOptionHolder) {
		h.SessionID = uint32(id)
	}
}

type Inbound struct {
	Source net.Destination

	Local net.Destination

	Gateway net.Destination

	Tag string

	Name string

	User *protocol.MemoryUser

	VlessRoute net.Port

	Conn net.Conn

	Timer *signal.ActivityTimer

	// CanSpliceCopy is shared by nested outbound and transfer goroutines.
	// 0: unset, 1: ready, 2: waiting for handshake, 3: disabled.
	CanSpliceCopy atomic.Int32
}

// Clone preserves the inbound metadata for a mux stream without copying the
// atomic state. Other metadata must remain immutable while the clone is made.
func (i *Inbound) Clone() *Inbound {
	clone := &Inbound{
		Source:     i.Source,
		Local:      i.Local,
		Gateway:    i.Gateway,
		Tag:        i.Tag,
		Name:       i.Name,
		User:       i.User,
		VlessRoute: i.VlessRoute,
		Conn:       i.Conn,
		Timer:      i.Timer,
	}
	clone.CanSpliceCopy.Store(i.CanSpliceCopy.Load())
	return clone
}

type Outbound struct {
	OriginalTarget net.Destination
	Target         net.Destination
	RouteTarget    net.Destination

	Gateway net.Address

	Tag string

	Name string

	Conn net.Conn

	// See Inbound.CanSpliceCopy. Never copy an Outbound after first use.
	CanSpliceCopy atomic.Int32
}

type SniffingRequest struct {
	ExcludeForDomain               []string
	OverrideDestinationForProtocol []string
	Enabled                        bool
	MetadataOnly                   bool
	RouteOnly                      bool
}

type Content struct {
	Protocol string

	SniffingRequest SniffingRequest

	Attributes map[string]string

	SkipDNSResolve bool
}

type Sockopt struct {
	Mark int32
}

func (c *Content) SetAttribute(name string, value string) {
	if c.Attributes == nil {
		c.Attributes = make(map[string]string)
	}
	c.Attributes[name] = value
}

func (c *Content) Attribute(name string) string {
	if c.Attributes == nil {
		return ""
	}
	return c.Attributes[name]
}
