package xdns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const compressionPointerLimit = 10

var (
	ErrZeroLengthLabel = errors.New("name contains a zero-length label")

	ErrLabelTooLong = errors.New("name contains a label longer than 63 octets")

	ErrNameTooLong = errors.New("name is longer than 255 octets")

	ErrReservedLabelType = errors.New("reserved label type")

	ErrTooManyPointers = errors.New("too many compression pointers")

	ErrTrailingBytes = errors.New("trailing bytes after message")

	ErrIntegerOverflow = errors.New("integer overflow")
)

const (
	RRTypeTXT = 16

	RRTypeOPT = 41

	ClassIN = 1

	RcodeNoError        = 0
	RcodeFormatError    = 1
	RcodeNameError      = 3
	RcodeNotImplemented = 4

	ExtendedRcodeBadVers = 16
)

type Name [][]byte

func NewName(labels [][]byte) (Name, error) {
	name := Name(labels)

	for _, label := range labels {
		if len(label) == 0 {
			return nil, ErrZeroLengthLabel
		}
		if len(label) > 63 {
			return nil, ErrLabelTooLong
		}
	}

	builder := newMessageBuilder()
	builder.WriteName(name)
	if len(builder.Bytes()) > 255 {
		return nil, ErrNameTooLong
	}
	return name, nil
}

func ParseName(s string) (Name, error) {
	b := bytes.TrimSuffix([]byte(s), []byte("."))
	if len(b) == 0 {

		return NewName([][]byte{})
	} else {
		return NewName(bytes.Split(b, []byte(".")))
	}
}

func (name Name) String() string {
	if len(name) == 0 {
		return "."
	}

	var buf strings.Builder
	for i, label := range name {
		if i > 0 {
			buf.WriteByte('.')
		}
		for _, b := range label {
			if b == '-' ||
				('0' <= b && b <= '9') ||
				('A' <= b && b <= 'Z') ||
				('a' <= b && b <= 'z') {
				buf.WriteByte(b)
			} else {
				fmt.Fprintf(&buf, "\\x%02x", b)
			}
		}
	}
	return buf.String()
}

func (name Name) TrimSuffix(suffix Name) (Name, bool) {
	if len(name) < len(suffix) {
		return nil, false
	}
	split := len(name) - len(suffix)
	fore, aft := name[:split], name[split:]
	for i := 0; i < len(aft); i++ {
		if !bytes.Equal(bytes.ToLower(aft[i]), bytes.ToLower(suffix[i])) {
			return nil, false
		}
	}
	return fore, true
}

type Message struct {
	ID    uint16
	Flags uint16

	Question   []Question
	Answer     []RR
	Authority  []RR
	Additional []RR
}

func (message *Message) Opcode() uint16 {
	return (message.Flags >> 11) & 0xf
}

func (message *Message) Rcode() uint16 {
	return message.Flags & 0x000f
}

type Question struct {
	Name  Name
	Type  uint16
	Class uint16
}

type RR struct {
	Name  Name
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

func readName(r io.ReadSeeker) (Name, error) {
	var labels [][]byte

	numPointers := 0

	var seekTo int64
loop:
	for {
		var labelType byte
		err := binary.Read(r, binary.BigEndian, &labelType)
		if err != nil {
			return nil, err
		}

		switch labelType & 0xc0 {
		case 0x00:

			length := int(labelType & 0x3f)
			if length == 0 {
				break loop
			}
			label := make([]byte, length)
			_, err := io.ReadFull(r, label)
			if err != nil {
				return nil, err
			}
			labels = append(labels, label)
		case 0xc0:

			upper := labelType & 0x3f
			var lower byte
			err := binary.Read(r, binary.BigEndian, &lower)
			if err != nil {
				return nil, err
			}
			offset := (uint16(upper) << 8) | uint16(lower)

			if numPointers == 0 {

				seekTo, err = r.Seek(0, io.SeekCurrent)
				if err != nil {
					return nil, err
				}
			}
			numPointers++
			if numPointers > compressionPointerLimit {
				return nil, ErrTooManyPointers
			}

			_, err = r.Seek(int64(offset), io.SeekStart)
			if err != nil {
				return nil, err
			}
		default:

			return nil, ErrReservedLabelType
		}
	}

	if numPointers > 0 {
		_, err := r.Seek(seekTo, io.SeekStart)
		if err != nil {
			return nil, err
		}
	}
	return NewName(labels)
}

func readQuestion(r io.ReadSeeker) (Question, error) {
	var question Question
	var err error
	question.Name, err = readName(r)
	if err != nil {
		return question, err
	}
	for _, ptr := range []*uint16{&question.Type, &question.Class} {
		err := binary.Read(r, binary.BigEndian, ptr)
		if err != nil {
			return question, err
		}
	}

	return question, nil
}

func readRR(r io.ReadSeeker) (RR, error) {
	var rr RR
	var err error
	rr.Name, err = readName(r)
	if err != nil {
		return rr, err
	}
	for _, ptr := range []*uint16{&rr.Type, &rr.Class} {
		err := binary.Read(r, binary.BigEndian, ptr)
		if err != nil {
			return rr, err
		}
	}
	err = binary.Read(r, binary.BigEndian, &rr.TTL)
	if err != nil {
		return rr, err
	}
	var rdLength uint16
	err = binary.Read(r, binary.BigEndian, &rdLength)
	if err != nil {
		return rr, err
	}
	rr.Data = make([]byte, rdLength)
	_, err = io.ReadFull(r, rr.Data)
	if err != nil {
		return rr, err
	}

	return rr, nil
}

func readMessage(r io.ReadSeeker) (Message, error) {
	var message Message

	var qdCount, anCount, nsCount, arCount uint16
	for _, ptr := range []*uint16{
		&message.ID, &message.Flags,
		&qdCount, &anCount, &nsCount, &arCount,
	} {
		err := binary.Read(r, binary.BigEndian, ptr)
		if err != nil {
			return message, err
		}
	}

	for i := 0; i < int(qdCount); i++ {
		question, err := readQuestion(r)
		if err != nil {
			return message, err
		}
		message.Question = append(message.Question, question)
	}

	for _, rec := range []struct {
		ptr   *[]RR
		count uint16
	}{
		{&message.Answer, anCount},
		{&message.Authority, nsCount},
		{&message.Additional, arCount},
	} {
		for i := 0; i < int(rec.count); i++ {
			rr, err := readRR(r)
			if err != nil {
				return message, err
			}
			*rec.ptr = append(*rec.ptr, rr)
		}
	}

	return message, nil
}

func MessageFromWireFormat(buf []byte) (Message, error) {
	r := bytes.NewReader(buf)
	message, err := readMessage(r)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	} else if err == nil {

		_, err = r.ReadByte()
		if err == io.EOF {
			err = nil
		} else if err == nil {
			err = ErrTrailingBytes
		}
	}
	return message, err
}

type messageBuilder struct {
	w         bytes.Buffer
	nameCache map[string]int
}

func newMessageBuilder() *messageBuilder {
	return &messageBuilder{
		nameCache: make(map[string]int),
	}
}

func (builder *messageBuilder) Bytes() []byte {
	return builder.w.Bytes()
}

func (builder *messageBuilder) WriteName(name Name) {

	for i := range name {

		if ptr, ok := builder.nameCache[name[i:].String()]; ok && ptr&0x3fff == ptr {

			binary.Write(&builder.w, binary.BigEndian, uint16(0xc000|ptr))
			return
		}

		builder.nameCache[name[i:].String()] = builder.w.Len()
		length := len(name[i])
		if length == 0 || length > 63 {
			panic(length)
		}
		builder.w.WriteByte(byte(length))
		builder.w.Write(name[i])
	}
	builder.w.WriteByte(0)
}

func (builder *messageBuilder) WriteQuestion(question *Question) {

	builder.WriteName(question.Name)
	binary.Write(&builder.w, binary.BigEndian, question.Type)
	binary.Write(&builder.w, binary.BigEndian, question.Class)
}

func (builder *messageBuilder) WriteRR(rr *RR) error {

	builder.WriteName(rr.Name)
	binary.Write(&builder.w, binary.BigEndian, rr.Type)
	binary.Write(&builder.w, binary.BigEndian, rr.Class)
	binary.Write(&builder.w, binary.BigEndian, rr.TTL)
	rdLength := uint16(len(rr.Data))
	if int(rdLength) != len(rr.Data) {
		return ErrIntegerOverflow
	}
	binary.Write(&builder.w, binary.BigEndian, rdLength)
	builder.w.Write(rr.Data)
	return nil
}

func (builder *messageBuilder) WriteMessage(message *Message) error {

	binary.Write(&builder.w, binary.BigEndian, message.ID)
	binary.Write(&builder.w, binary.BigEndian, message.Flags)
	for _, count := range []int{
		len(message.Question),
		len(message.Answer),
		len(message.Authority),
		len(message.Additional),
	} {
		count16 := uint16(count)
		if int(count16) != count {
			return ErrIntegerOverflow
		}
		binary.Write(&builder.w, binary.BigEndian, count16)
	}

	for _, question := range message.Question {
		builder.WriteQuestion(&question)
	}

	for _, rrs := range [][]RR{message.Answer, message.Authority, message.Additional} {
		for _, rr := range rrs {
			err := builder.WriteRR(&rr)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (message *Message) WireFormat() ([]byte, error) {
	builder := newMessageBuilder()
	err := builder.WriteMessage(message)
	if err != nil {
		return nil, err
	}
	return builder.Bytes(), nil
}

func DecodeRDataTXT(p []byte) ([]byte, error) {
	var buf bytes.Buffer
	for {
		if len(p) == 0 {
			return nil, io.ErrUnexpectedEOF
		}
		n := int(p[0])
		p = p[1:]
		if len(p) < n {
			return nil, io.ErrUnexpectedEOF
		}
		buf.Write(p[:n])
		p = p[n:]
		if len(p) == 0 {
			break
		}
	}
	return buf.Bytes(), nil
}

func EncodeRDataTXT(p []byte) []byte {

	var buf bytes.Buffer
	for len(p) > 255 {
		buf.WriteByte(255)
		buf.Write(p[:255])
		p = p[255:]
	}

	buf.WriteByte(byte(len(p)))
	buf.Write(p)
	return buf.Bytes()
}
