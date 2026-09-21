//go:build darwin

package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	utunControlName = "com.apple.net.utun_control"
	sysprotoControl = 2
	gateway         = "169.254.10.1/30"
	utunHeaderSize  = 4
)

const (
	SIOCAIFADDR6          = 2155899162
	IN6_IFF_NODAD         = 0x0020
	IN6_IFF_SECURED       = 0x0400
	ND6_INFINITE_LIFETIME = 0xFFFFFFFF
)

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

type DarwinTun struct {
	tunFile *os.File
	options TunOptions
	ownsFd  bool
}

var _ Tun = (*DarwinTun)(nil)
var _ GVisorTun = (*DarwinTun)(nil)
var _ GVisorDevice = (*DarwinTun)(nil)

func NewTun(options TunOptions) (Tun, error) {

	fdStr := platform.NewEnvFlag(platform.TunFdKey).GetValue(func() string { return "" })
	if fdStr != "" {

		fd, err := strconv.Atoi(fdStr)
		if err != nil {
			return nil, err
		}

		if err = unix.SetNonblock(fd, true); err != nil {
			return nil, err
		}

		return &DarwinTun{
			tunFile: os.NewFile(uintptr(fd), "utun"),
			options: options,
			ownsFd:  false,
		}, nil
	}

	tunFile, err := open(options.Name)
	if err != nil {
		return nil, err
	}

	err = setup(options.Name, options.MTU)
	if err != nil {
		_ = tunFile.Close()
		return nil, err
	}

	return &DarwinTun{
		tunFile: tunFile,
		options: options,
		ownsFd:  true,
	}, nil
}

func (t *DarwinTun) Start() error {
	return nil
}

func (t *DarwinTun) Close() error {
	if t.ownsFd {
		return t.tunFile.Close()
	}

	return nil
}

func (t *DarwinTun) WritePacket(packet *stack.PacketBuffer) tcpip.Error {

	b := buf.NewWithSize(int32(t.options.MTU) + utunHeaderSize)
	defer b.Release()

	_, _ = b.Write([]byte{0x0, 0x0, 0x0, 0x0})

	for _, packetElement := range packet.AsSlices() {
		_, _ = b.Write(packetElement)
	}

	var family byte
	switch b.Byte(4) >> 4 {
	case 4:
		family = unix.AF_INET
	case 6:
		family = unix.AF_INET6
	default:
		return &tcpip.ErrAborted{}
	}
	b.SetByte(3, family)

	if _, err := t.tunFile.Write(b.Bytes()); err != nil {
		if errors.Is(err, unix.EAGAIN) {
			return &tcpip.ErrWouldBlock{}
		}
		return &tcpip.ErrAborted{}
	}
	return nil
}

func (t *DarwinTun) ReadPacket() (byte, *stack.PacketBuffer, error) {

	b := buf.NewWithSize(int32(t.options.MTU) + utunHeaderSize)

	n, err := b.ReadFrom(t.tunFile)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		b.Release()
		return 0, nil, ErrQueueEmpty
	}
	if err != nil {
		b.Release()
		return 0, nil, err
	}

	if n <= utunHeaderSize {
		b.Release()
		return 0, nil, ErrQueueEmpty
	}

	version := b.Byte(utunHeaderSize) >> 4
	packetBuffer := buffer.MakeWithData(b.BytesFrom(utunHeaderSize))
	return version, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:           packetBuffer,
		IsForwardedPacket: true,
		OnRelease: func() {
			b.Release()
		},
	}), nil
}

func (t *DarwinTun) Wait() {
	procyield(1)
}

func (t *DarwinTun) newEndpoint() (stack.LinkEndpoint, error) {
	return &LinkEndpoint{deviceMTU: t.options.MTU, device: t}, nil
}

func open(name string) (*os.File, error) {
	ifIndex := -1
	_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
	if err != nil || ifIndex < 0 {
		return nil, errors.New("interface name must be utunN, where N is a number, e.g. utun9, utun11 and so on")
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, err
	}

	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	sockaddr := &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(ifIndex) + 1,
	}
	if err := unix.Connect(fd, sockaddr); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	return os.NewFile(uintptr(fd), name), nil
}

func setup(name string, MTU uint32) error {
	if err := setMTU(name, MTU); err != nil {
		return err
	}

	syntheticIP, _ := netip.ParsePrefix(gateway)
	if err := setIPAddress(name, syntheticIP); err != nil {
		return err
	}

	return nil
}

func setMTU(name string, mtu uint32) error {
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(socket)

	ifr := unix.IfreqMTU{MTU: int32(mtu)}
	copy(ifr.Name[:], name)
	return unix.IoctlSetIfreqMTU(socket, &ifr)
}

type ifAliasReq4 struct {
	Name    [unix.IFNAMSIZ]byte
	Addr    unix.RawSockaddrInet4
	Dstaddr unix.RawSockaddrInet4
	Mask    unix.RawSockaddrInet4
}

type ifAliasReq6 struct {
	Name     [unix.IFNAMSIZ]byte
	Addr     unix.RawSockaddrInet6
	Dstaddr  unix.RawSockaddrInet6
	Mask     unix.RawSockaddrInet6
	Flags    uint32
	Lifetime addrLifetime6
}

type addrLifetime6 struct {
	Expire    float64
	Preferred float64
	Vltime    uint32
	Pltime    uint32
}

func setIPAddress(name string, gateway netip.Prefix) error {
	socket4, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(socket4)

	local4 := gateway.Addr().As4()
	local4[3]++

	ifReq4 := ifAliasReq4{
		Addr: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   local4,
		},
		Dstaddr: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   gateway.Addr().As4(),
		},
		Mask: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   netip.MustParseAddr(net.IP(net.CIDRMask(gateway.Bits(), 32)).String()).As4(),
		},
	}
	copy(ifReq4.Name[:], name)
	if err = ioctlPtr(socket4, unix.SIOCAIFADDR, unsafe.Pointer(&ifReq4)); err != nil {
		return os.NewSyscallError("SIOCAIFADDR", err)
	}

	socket6, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(socket6)

	local6 := netip.AddrFrom16([16]byte{0: 0xfe, 1: 0x80, 12: local4[0], 13: local4[1], 14: local4[2], 15: local4[3]})

	ifReq6 := ifAliasReq6{
		Addr: unix.RawSockaddrInet6{
			Len:    unix.SizeofSockaddrInet6,
			Family: unix.AF_INET6,
			Addr:   local6.As16(),
		},
		Mask: unix.RawSockaddrInet6{
			Len:    unix.SizeofSockaddrInet6,
			Family: unix.AF_INET6,
			Addr:   netip.MustParseAddr(net.IP(net.CIDRMask(64, 128)).String()).As16(),
		},
		Flags: IN6_IFF_NODAD,
		Lifetime: addrLifetime6{
			Vltime: ND6_INFINITE_LIFETIME,
			Pltime: ND6_INFINITE_LIFETIME,
		},
	}

	copy(ifReq6.Name[:], name)
	if err = ioctlPtr(socket6, SIOCAIFADDR6, unsafe.Pointer(&ifReq6)); err != nil {
		return os.NewSyscallError("SIOCAIFADDR6", err)
	}

	return nil
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}
