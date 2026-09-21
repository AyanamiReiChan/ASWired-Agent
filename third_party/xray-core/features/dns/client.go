package dns

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features"
)

type IPOption struct {
	IPv4Enable bool
	IPv6Enable bool
	FakeEnable bool
}

type Client interface {
	features.Feature

	LookupIP(domain string, option IPOption) ([]net.IP, uint32, error)
}

func ClientType() interface{} {
	return (*Client)(nil)
}

var ErrEmptyResponse = errors.New("empty response")

const DefaultTTL = 300

type RCodeError uint16

func (e RCodeError) Error() string {
	return serial.Concat("rcode: ", uint16(e))
}

func (RCodeError) IP() net.IP {
	panic("Calling IP() on a RCodeError.")
}

func (RCodeError) Domain() string {
	panic("Calling Domain() on a RCodeError.")
}

func (RCodeError) Family() net.AddressFamily {
	panic("Calling Family() on a RCodeError.")
}

func (e RCodeError) String() string {
	return e.Error()
}

var _ net.Address = (*RCodeError)(nil)

func RCodeFromError(err error) uint16 {
	if err == nil {
		return 0
	}
	cause := errors.Cause(err)
	if r, ok := cause.(RCodeError); ok {
		return uint16(r)
	}
	return 0
}
