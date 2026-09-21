package buf

import (
	"io"

	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

const (
	Size = 8192
)

var ErrBufferFull = errors.New("buffer is full")

var pool = bytespool.GetPool(Size)

type ownership uint8

const (
	managed ownership = iota
	unmanaged
	bytespools
)

type Buffer struct {
	v         []byte
	start     int32
	end       int32
	ownership ownership
	UDP       *net.Destination
}

func New() *Buffer {
	buf := pool.Get().([]byte)
	if cap(buf) >= Size {
		buf = buf[:Size]
	} else {
		buf = make([]byte, Size)
	}

	return &Buffer{
		v: buf,
	}
}

func NewExisted(b []byte) *Buffer {
	if cap(b) < Size {
		panic("Invalid buffer")
	}

	oLen := len(b)
	if oLen < Size {
		b = b[:Size]
	}

	return &Buffer{
		v:   b,
		end: int32(oLen),
	}
}

func FromBytes(b []byte) *Buffer {
	return &Buffer{
		v:         b,
		end:       int32(len(b)),
		ownership: unmanaged,
	}
}

func StackNew() Buffer {
	buf := pool.Get().([]byte)
	if cap(buf) >= Size {
		buf = buf[:Size]
	} else {
		buf = make([]byte, Size)
	}

	return Buffer{
		v: buf,
	}
}

func NewWithSize(size int32) *Buffer {
	return &Buffer{
		v:         bytespool.Alloc(size),
		ownership: bytespools,
	}
}

func (b *Buffer) Release() {
	if b == nil || b.v == nil || b.ownership == unmanaged {
		return
	}

	p := b.v
	b.v = nil
	b.Clear()

	switch b.ownership {
	case managed:
		if cap(p) == Size {
			pool.Put(p)
		}
	case bytespools:
		bytespool.Free(p)
	}
	b.UDP = nil
}

func (b *Buffer) Clear() {
	b.start = 0
	b.end = 0
}

func (b *Buffer) Byte(index int32) byte {
	return b.v[b.start+index]
}

func (b *Buffer) SetByte(index int32, value byte) {
	b.v[b.start+index] = value
}

func (b *Buffer) Bytes() []byte {
	return b.v[b.start:b.end]
}

func (b *Buffer) Extend(n int32) []byte {
	end := b.end + n
	if end > int32(len(b.v)) {
		panic("extending out of bound")
	}
	ext := b.v[b.end:end]
	b.end = end
	clear(ext)
	return ext
}

func (b *Buffer) BytesRange(from, to int32) []byte {
	if from < 0 {
		from += b.Len()
	}
	if to < 0 {
		to += b.Len()
	}
	return b.v[b.start+from : b.start+to]
}

func (b *Buffer) BytesFrom(from int32) []byte {
	if from < 0 {
		from += b.Len()
	}
	return b.v[b.start+from : b.end]
}

func (b *Buffer) BytesTo(to int32) []byte {
	if to < 0 {
		to += b.Len()
	}
	if to < 0 {
		to = 0
	}
	return b.v[b.start : b.start+to]
}

func (b *Buffer) Check() {
	if b.start < 0 {
		b.start = 0
	}
	if b.end < 0 {
		b.end = 0
	}
	if b.start > b.end {
		b.start = b.end
	}
}

func (b *Buffer) Resize(from, to int32) {
	oldEnd := b.end
	if from < 0 {
		from += b.Len()
	}
	if to < 0 {
		to += b.Len()
	}
	if to < from {
		panic("Invalid slice")
	}
	b.end = b.start + to
	b.start += from
	b.Check()
	if b.end > oldEnd {
		clear(b.v[oldEnd:b.end])
	}
}

func (b *Buffer) Advance(from int32) {
	if from < 0 {
		from += b.Len()
	}
	b.start += from
	b.Check()
}

func (b *Buffer) Len() int32 {
	if b == nil {
		return 0
	}
	return b.end - b.start
}

func (b *Buffer) Cap() int32 {
	if b == nil {
		return 0
	}
	return int32(len(b.v))
}

func (b *Buffer) Available() int32 {
	if b == nil {
		return 0
	}
	return int32(len(b.v)) - b.end
}

func (b *Buffer) IsEmpty() bool {
	return b.Len() == 0
}

func (b *Buffer) IsFull() bool {
	return b != nil && b.end == int32(len(b.v))
}

func (b *Buffer) Write(data []byte) (int, error) {
	nBytes := copy(b.v[b.end:], data)
	b.end += int32(nBytes)
	if nBytes < len(data) {
		return nBytes, ErrBufferFull
	}
	return nBytes, nil
}

func (b *Buffer) WriteByte(v byte) error {
	if b.IsFull() {
		return ErrBufferFull
	}
	b.v[b.end] = v
	b.end++
	return nil
}

func (b *Buffer) WriteString(s string) (int, error) {
	return b.Write([]byte(s))
}

func (b *Buffer) ReadByte() (byte, error) {
	if b.start == b.end {
		return 0, io.EOF
	}

	nb := b.v[b.start]
	b.start++
	return nb, nil
}

func (b *Buffer) ReadBytes(length int32) ([]byte, error) {
	if b.end-b.start < length {
		return nil, io.EOF
	}

	nb := b.v[b.start : b.start+length]
	b.start += length
	return nb, nil
}

func (b *Buffer) Read(data []byte) (int, error) {
	if b.Len() == 0 {
		return 0, io.EOF
	}
	nBytes := copy(data, b.v[b.start:b.end])
	if int32(nBytes) == b.Len() {
		b.Clear()
	} else {
		b.start += int32(nBytes)
	}
	return nBytes, nil
}

func (b *Buffer) ReadFrom(reader io.Reader) (int64, error) {
	n, err := reader.Read(b.v[b.end:])
	b.end += int32(n)
	return int64(n), err
}

func (b *Buffer) ReadFullFrom(reader io.Reader, size int32) (int64, error) {
	end := b.end + size
	if end > int32(len(b.v)) {
		v := end
		return 0, errors.New("out of bound: ", v)
	}
	n, err := io.ReadFull(reader, b.v[b.end:end])
	b.end += int32(n)
	return int64(n), err
}

func (b *Buffer) String() string {
	return string(b.Bytes())
}
