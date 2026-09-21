package socks

import (
	"net"
	"sync"
)

type UDPFilter struct {
	ips sync.Map
}

func (f *UDPFilter) Add(addr net.Addr) bool {
	ip, _, _ := net.SplitHostPort(addr.String())
	f.ips.Store(ip, true)
	return true
}

func (f *UDPFilter) Check(addr net.Addr) bool {
	ip, _, _ := net.SplitHostPort(addr.String())
	_, ok := f.ips.Load(ip)
	return ok
}
