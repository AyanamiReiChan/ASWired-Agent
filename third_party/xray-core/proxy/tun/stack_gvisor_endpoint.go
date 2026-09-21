package tun

import (
	"context"
	"errors"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var ErrQueueEmpty = errors.New("queue is empty")

type GVisorDevice interface {
	WritePacket(packet *stack.PacketBuffer) tcpip.Error
	ReadPacket() (byte, *stack.PacketBuffer, error)
	Wait()
}

var _ stack.LinkEndpoint = (*LinkEndpoint)(nil)

type LinkEndpoint struct {
	deviceMTU        uint32
	device           GVisorDevice
	dispatcherCancel context.CancelFunc
}

func (e *LinkEndpoint) MTU() uint32 {
	return e.deviceMTU
}

func (e *LinkEndpoint) SetMTU(_ uint32) {

}

func (e *LinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *LinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *LinkEndpoint) SetLinkAddress(_ tcpip.LinkAddress) {

}

func (e *LinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (e *LinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if e.dispatcherCancel != nil {
		e.dispatcherCancel()
		e.dispatcherCancel = nil
	}

	if dispatcher != nil {
		ctx, cancel := context.WithCancel(context.Background())
		go e.dispatchLoop(ctx, dispatcher)
		e.dispatcherCancel = cancel
	}
}

func (e *LinkEndpoint) IsAttached() bool {
	return e.dispatcherCancel != nil
}

func (e *LinkEndpoint) Wait() {

}

func (e *LinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *LinkEndpoint) AddHeader(buffer *stack.PacketBuffer) {

}

func (e *LinkEndpoint) ParseHeader(ptr *stack.PacketBuffer) bool {
	return true
}

func (e *LinkEndpoint) Close() {
	if e.dispatcherCancel != nil {
		e.dispatcherCancel()
		e.dispatcherCancel = nil
	}
}

func (e *LinkEndpoint) SetOnCloseAction(_ func()) {

}

func (e *LinkEndpoint) WritePackets(packetBufferList stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	var err tcpip.Error

	for _, packetBuffer := range packetBufferList.AsSlice() {
		err = e.device.WritePacket(packetBuffer)
		if err != nil {
			return n, &tcpip.ErrAborted{}
		}
		n++
	}

	return n, nil
}

func (e *LinkEndpoint) dispatchLoop(ctx context.Context, dispatcher stack.NetworkDispatcher) {
	var networkProtocolNumber tcpip.NetworkProtocolNumber
	var version byte
	var packet *stack.PacketBuffer
	var err error

	for {
		select {
		case <-ctx.Done():
			return
		default:
			version, packet, err = e.device.ReadPacket()

			if errors.Is(err, ErrQueueEmpty) {
				e.device.Wait()
				continue
			}

			if err != nil {
				e.Attach(nil)
				return
			}

			switch version {
			case 4:
				networkProtocolNumber = header.IPv4ProtocolNumber
			case 6:
				networkProtocolNumber = header.IPv6ProtocolNumber
			default:

				packet.DecRef()
				continue
			}

			dispatcher.DeliverNetworkPacket(networkProtocolNumber, packet)

			packet.DecRef()
		}
	}
}
