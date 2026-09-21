//go:build windows

package tun

import (
	"crypto/md5"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

type WindowsTun struct {
	options  TunOptions
	adapter  *wintun.Adapter
	session  wintun.Session
	readWait windows.Handle
	MTU      uint32
}

var _ Tun = (*WindowsTun)(nil)

var _ GVisorTun = (*WindowsTun)(nil)

var _ GVisorDevice = (*WindowsTun)(nil)

func NewTun(options TunOptions) (Tun, error) {

	adapter, err := open(options.Name)
	if err != nil {
		return nil, err
	}

	session, err := adapter.StartSession(0x800000)
	if err != nil {
		_ = adapter.Close()
		return nil, err
	}

	tun := &WindowsTun{
		options:  options,
		adapter:  adapter,
		session:  session,
		readWait: session.ReadWaitEvent(),

		MTU: wintun.PacketSizeMax,
	}

	return tun, nil
}

func open(name string) (*wintun.Adapter, error) {

	id := md5.Sum([]byte(name))
	guid := (*windows.GUID)(unsafe.Pointer(&id[0]))

	adapter, err := wintun.OpenAdapter(name)
	if err == nil {
		return adapter, nil
	}

	adapter, err = wintun.CreateAdapter(name, "Xray", guid)
	if err == nil {
		return adapter, nil
	}
	return nil, err
}

func (t *WindowsTun) Start() error {
	return nil
}

func (t *WindowsTun) Close() error {
	t.session.End()
	_ = t.adapter.Close()

	return nil
}

func (t *WindowsTun) WritePacket(packetBuffer *stack.PacketBuffer) tcpip.Error {

	packet, err := t.session.AllocateSendPacket(packetBuffer.Size())
	if err != nil {
		return &tcpip.ErrAborted{}
	}

	var index int
	for _, packetElement := range packetBuffer.AsSlices() {
		index += copy(packet[index:], packetElement)
	}

	t.session.SendPacket(packet)

	return nil
}

func (t *WindowsTun) ReadPacket() (byte, *stack.PacketBuffer, error) {
	packet, err := t.session.ReceivePacket()
	if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
		return 0, nil, ErrQueueEmpty
	}
	if err != nil {
		return 0, nil, err
	}

	version := packet[0] >> 4
	packetBuffer := buffer.MakeWithView(buffer.NewViewWithData(packet))
	return version, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:           packetBuffer,
		IsForwardedPacket: true,
		OnRelease: func() {
			t.session.ReleaseReceivePacket(packet)
		},
	}), nil
}

func (t *WindowsTun) Wait() {
	procyield(1)
	_, _ = windows.WaitForSingleObject(t.readWait, windows.INFINITE)
}

func (t *WindowsTun) newEndpoint() (stack.LinkEndpoint, error) {
	return &LinkEndpoint{deviceMTU: t.options.MTU, device: t}, nil
}
