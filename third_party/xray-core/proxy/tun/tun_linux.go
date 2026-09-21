//go:build linux && !android

package tun

import (
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type LinuxTun struct {
	tunFd   int
	tunLink netlink.Link
	options TunOptions
}

var _ Tun = (*LinuxTun)(nil)

var _ GVisorTun = (*LinuxTun)(nil)

func NewTun(options TunOptions) (Tun, error) {
	tunFd, err := open(options.Name)
	if err != nil {
		return nil, err
	}

	tunLink, err := setup(options.Name, int(options.MTU))
	if err != nil {
		_ = unix.Close(tunFd)
		return nil, err
	}

	linuxTun := &LinuxTun{
		tunFd:   tunFd,
		tunLink: tunLink,
		options: options,
	}

	return linuxTun, nil
}

func open(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, err
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return 0, err
	}

	flags := unix.IFF_TUN | unix.IFF_NO_PI
	ifr.SetUint16(uint16(flags))
	err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	if err != nil {
		_ = unix.Close(fd)
		return 0, err
	}

	err = unix.SetNonblock(fd, true)
	if err != nil {
		_ = unix.Close(fd)
		return 0, err
	}

	return fd, nil
}

func setup(name string, MTU int) (netlink.Link, error) {
	tunLink, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}

	err = netlink.LinkSetMTU(tunLink, MTU)
	if err != nil {
		_ = netlink.LinkSetDown(tunLink)
		return nil, err
	}

	return tunLink, nil
}

func (t *LinuxTun) Start() error {
	err := netlink.LinkSetUp(t.tunLink)
	if err != nil {
		return err
	}

	return nil
}

func (t *LinuxTun) Close() error {
	_ = netlink.LinkSetDown(t.tunLink)
	_ = unix.Close(t.tunFd)

	return nil
}

func (t *LinuxTun) newEndpoint() (stack.LinkEndpoint, error) {
	return fdbased.New(&fdbased.Options{
		FDs:               []int{t.tunFd},
		MTU:               t.options.MTU,
		RXChecksumOffload: true,
	})
}
