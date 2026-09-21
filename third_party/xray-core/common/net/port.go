package net

import (
	"encoding/binary"
	"strconv"

	"github.com/xtls/xray-core/common/errors"
)

type Port uint16

func PortFromBytes(port []byte) Port {
	return Port(binary.BigEndian.Uint16(port))
}

func PortFromInt(val uint32) (Port, error) {
	if val > 65535 {
		return Port(0), errors.New("invalid port range: ", val)
	}
	return Port(val), nil
}

func PortFromString(s string) (Port, error) {
	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return Port(0), errors.New("invalid port range: ", s)
	}
	return PortFromInt(uint32(val))
}

func (p Port) Value() uint16 {
	return uint16(p)
}

func (p Port) String() string {
	return strconv.Itoa(int(p))
}

func (p *PortRange) FromPort() Port {
	return Port(p.From)
}

func (p *PortRange) ToPort() Port {
	return Port(p.To)
}

func (p *PortRange) Contains(port Port) bool {
	return p.FromPort() <= port && port <= p.ToPort()
}

func SinglePortRange(p Port) *PortRange {
	return &PortRange{
		From: uint32(p),
		To:   uint32(p),
	}
}

type MemoryPortRange struct {
	From Port
	To   Port
}

func (r MemoryPortRange) Contains(port Port) bool {
	return r.From <= port && port <= r.To
}

type MemoryPortList []MemoryPortRange

func PortListFromProto(l *PortList) MemoryPortList {
	mpl := make(MemoryPortList, 0, len(l.Range))
	for _, r := range l.Range {
		mpl = append(mpl, MemoryPortRange{From: Port(r.From), To: Port(r.To)})
	}
	return mpl
}

func (l *PortList) Ports() []uint32 {
	var ports []uint32
	for _, r := range l.Range {
		for i := uint32(r.From); i <= uint32(r.To); i++ {
			ports = append(ports, i)
		}
	}
	return ports
}

func (mpl MemoryPortList) Contains(port Port) bool {
	for _, pr := range mpl {
		if pr.Contains(port) {
			return true
		}
	}
	return false
}
