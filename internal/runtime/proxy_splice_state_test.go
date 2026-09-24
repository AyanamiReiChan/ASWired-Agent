package runtime

import (
	"sync"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func TestProxyIPv6GuardSessionSpliceStateClone(t *testing.T) {
	inbound := &session.Inbound{
		Source:     xnet.TCPDestination(xnet.LocalHostIP, 1234),
		Local:      xnet.TCPDestination(xnet.LocalHostIP, 4321),
		Gateway:    xnet.UDPDestination(xnet.LocalHostIP, 123),
		Tag:        "business-entry",
		Name:       "socks",
		User:       &protocol.MemoryUser{Email: "splice-test@example.invalid"},
		VlessRoute: 456,
	}
	inbound.CanSpliceCopy.Store(2)
	clone := inbound.Clone()
	if clone.Source != inbound.Source || clone.Local != inbound.Local || clone.Gateway != inbound.Gateway ||
		clone.Tag != inbound.Tag || clone.Name != inbound.Name || clone.User != inbound.User || clone.VlessRoute != inbound.VlessRoute {
		t.Fatal("mux clone lost inbound metadata")
	}
	if !clone.CanSpliceCopy.CompareAndSwap(2, 1) || inbound.CanSpliceCopy.Load() != 2 {
		t.Fatal("mux clone shares mutable splice state with its parent")
	}

	// Mux cloning must atomically snapshot readiness while the parent transfer
	// changes state. This runs on every OS, including hosts without raw splice.
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for i := 0; i < 1000; i++ {
			inbound.CanSpliceCopy.Store(2)
			inbound.CanSpliceCopy.CompareAndSwap(2, 1)
			inbound.CanSpliceCopy.Store(3)
		}
	}()
	for i := 0; i < 1000; i++ {
		state := inbound.Clone().CanSpliceCopy.Load()
		if state < 1 || state > 3 {
			t.Errorf("invalid cloned readiness: %d", state)
		}
	}
	workers.Wait()
	if inbound.CanSpliceCopy.CompareAndSwap(2, 1) || inbound.CanSpliceCopy.Load() != 3 {
		t.Fatal("late handshake re-enabled disabled splice state")
	}
}
