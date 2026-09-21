package dns

import (
	"encoding/binary"
	"net"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
)

func packDomainName(s string, msg []byte) (off1 int, err error) {
	off := 0
	ls := len(s)

	var (
		begin int
		bs    []byte
	)
	for i := 0; i < ls; i++ {
		var c byte
		if bs == nil {
			c = s[i]
		} else {
			c = bs[i]
		}

		switch c {
		case '\\':
			if off+1 > len(msg) {
				return len(msg), errors.New("buffer size too small")
			}

			if bs == nil {
				bs = []byte(s)
			}

			copy(bs[i:ls-1], bs[i+1:])
			ls--
		case '.':
			labelLen := i - begin
			if labelLen >= 1<<6 {
				return len(msg), errors.New("bad rdata")
			}

			if off+1+labelLen > len(msg) {
				return len(msg), errors.New("buffer size too small")
			}

			msg[off] = byte(labelLen)

			if bs == nil {
				copy(msg[off+1:], s[begin:i])
			} else {
				copy(msg[off+1:], bs[begin:i])
			}
			off += 1 + labelLen
			begin = i + 1
		default:
		}
	}

	if off < len(msg) {
		msg[off] = 0
	}

	return off + 1, nil
}

type dns struct {
	header []byte
}

func (h *dns) Size() int {
	return len(h.header)
}

func (h *dns) Serialize(b []byte) {
	copy(b, h.header)
	binary.BigEndian.PutUint16(b[0:], dice.RollUint16())
}

type dnsConn struct {
	net.PacketConn
	header *dns
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	var header []byte
	header = binary.BigEndian.AppendUint16(header, 0x0000)
	header = binary.BigEndian.AppendUint16(header, 0x0100)
	header = binary.BigEndian.AppendUint16(header, 0x0001)
	header = binary.BigEndian.AppendUint16(header, 0x0000)
	header = binary.BigEndian.AppendUint16(header, 0x0000)
	header = binary.BigEndian.AppendUint16(header, 0x0000)
	buf := make([]byte, 0x100)
	off1, err := packDomainName(c.Domain+".", buf)
	if err != nil {
		return nil, err
	}
	header = append(header, buf[:off1]...)
	header = binary.BigEndian.AppendUint16(header, 0x0001)
	header = binary.BigEndian.AppendUint16(header, 0x0001)

	conn := &dnsConn{
		PacketConn: raw,
		header: &dns{
			header: header,
		},
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *dnsConn) Size() int {
	return c.header.Size()
}

func (c *dnsConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return len(p) - c.header.Size(), addr, nil
}

func (c *dnsConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.header.Serialize(p)

	return len(p), nil
}
