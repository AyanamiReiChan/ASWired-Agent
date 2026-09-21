package quic

import (
	"crypto"
	"crypto/aes"
	"crypto/tls"
	"encoding/binary"
	"io"

	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	ptls "github.com/xtls/xray-core/common/protocol/tls"
	"golang.org/x/crypto/hkdf"
)

type SniffHeader struct {
	domain string
}

func (s SniffHeader) Protocol() string {
	return "quic"
}

func (s SniffHeader) Domain() string {
	return s.domain
}

const (
	versionDraft29 uint32 = 0xff00001d
	version1       uint32 = 0x1
)

var (
	quicSaltOld  = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSalt     = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initialSuite = &CipherSuiteTLS13{
		ID:     tls.TLS_AES_128_GCM_SHA256,
		KeyLen: 16,
		AEAD:   AEADAESGCMTLS13,
		Hash:   crypto.SHA256,
	}
	errNotQuic        = errors.New("not quic")
	errNotQuicInitial = errors.New("not initial packet")
)

func SniffQUIC(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}

	cryptoLen := int32(0)
	cryptoDataBuf := buf.NewWithSize(32767)
	defer cryptoDataBuf.Release()
	cache := buf.New()
	defer cache.Release()

	for len(b) > 0 {
		buffer := buf.FromBytes(b)
		typeByte, err := buffer.ReadByte()
		if err != nil {
			return nil, errNotQuic
		}

		isLongHeader := typeByte&0x80 > 0
		if !isLongHeader || typeByte&0x40 == 0 {
			return nil, errNotQuicInitial
		}

		vb, err := buffer.ReadBytes(4)
		if err != nil {
			return nil, errNotQuic
		}

		versionNumber := binary.BigEndian.Uint32(vb)
		if versionNumber != 0 && typeByte&0x40 == 0 {
			return nil, errNotQuic
		} else if versionNumber != versionDraft29 && versionNumber != version1 {
			return nil, errNotQuic
		}

		packetType := (typeByte & 0x30) >> 4
		isQuicInitial := packetType == 0x0

		var destConnID []byte
		if l, err := buffer.ReadByte(); err != nil {
			return nil, errNotQuic
		} else if destConnID, err = buffer.ReadBytes(int32(l)); err != nil {
			return nil, errNotQuic
		}

		if l, err := buffer.ReadByte(); err != nil {
			return nil, errNotQuic
		} else if common.Error2(buffer.ReadBytes(int32(l))) != nil {
			return nil, errNotQuic
		}

		if isQuicInitial {
			tokenLen, err := quicvarint.Read(buffer)
			if err != nil || tokenLen > uint64(len(b)) {
				return nil, errNotQuic
			}

			if _, err = buffer.ReadBytes(int32(tokenLen)); err != nil {
				return nil, errNotQuic
			}
		}

		packetLen, err := quicvarint.Read(buffer)
		if err != nil {
			return nil, errNotQuic
		}

		if packetLen < 4 {
			return nil, errNotQuic
		}

		hdrLen := len(b) - int(buffer.Len())
		if len(b) < hdrLen+int(packetLen) {
			return nil, common.ErrNoClue
		}

		restPayload := b[hdrLen+int(packetLen):]
		if !isQuicInitial {
			b = restPayload
			continue
		}

		var salt []byte
		if versionNumber == version1 {
			salt = quicSalt
		} else {
			salt = quicSaltOld
		}
		initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, salt)
		secret := hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())
		hpKey := hkdfExpandLabel(initialSuite.Hash, secret, []byte{}, "quic hp", initialSuite.KeyLen)
		block, err := aes.NewCipher(hpKey)
		if err != nil {
			return nil, err
		}

		cache.Clear()
		mask := cache.Extend(int32(block.BlockSize()))
		block.Encrypt(mask, b[hdrLen+4:hdrLen+4+len(mask)])
		b[0] ^= mask[0] & 0xf
		packetNumberLength := int(b[0]&0x3 + 1)
		for i := range packetNumberLength {
			b[hdrLen+i] ^= mask[i+1]
		}

		key := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic key", 16)
		iv := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic iv", 12)
		cipher := AEADAESGCMTLS13(key, iv)

		nonce := cache.Extend(int32(cipher.NonceSize()))
		_, err = buffer.Read(nonce[len(nonce)-packetNumberLength:])
		if err != nil {
			return nil, err
		}

		extHdrLen := hdrLen + packetNumberLength
		data := b[extHdrLen : int(packetLen)+hdrLen]
		decrypted, err := cipher.Open(b[extHdrLen:extHdrLen], nonce, data, b[:extHdrLen])
		if err != nil {
			return nil, err
		}
		buffer = buf.FromBytes(decrypted)
		for !buffer.IsEmpty() {
			frameType, _ := buffer.ReadByte()
			for frameType == 0x0 && !buffer.IsEmpty() {
				frameType, _ = buffer.ReadByte()
			}
			switch frameType {
			case 0x00:
			case 0x01:
			case 0x02, 0x03:
				if _, err = quicvarint.Read(buffer); err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				ackRangeCount, err := quicvarint.Read(buffer)
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				for i := 0; i < int(ackRangeCount); i++ {
					if _, err = quicvarint.Read(buffer); err != nil {
						return nil, io.ErrUnexpectedEOF
					}
					if _, err = quicvarint.Read(buffer); err != nil {
						return nil, io.ErrUnexpectedEOF
					}
				}
				if frameType == 0x03 {
					if _, err = quicvarint.Read(buffer); err != nil {
						return nil, io.ErrUnexpectedEOF
					}
					if _, err = quicvarint.Read(buffer); err != nil {
						return nil, io.ErrUnexpectedEOF
					}
					if _, err = quicvarint.Read(buffer); err != nil { //nolint:misspell // Field: ECN Counts -> ECT-CE Count
						return nil, io.ErrUnexpectedEOF
					}
				}
			case 0x06:
				offset, err := quicvarint.Read(buffer)
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				length, err := quicvarint.Read(buffer)
				if err != nil || length > uint64(buffer.Len()) {
					return nil, io.ErrUnexpectedEOF
				}
				currentCryptoLen := int32(offset + length)
				if cryptoLen < currentCryptoLen {
					if cryptoDataBuf.Cap() < currentCryptoLen {
						return nil, io.ErrShortBuffer
					}
					cryptoDataBuf.Extend(currentCryptoLen - cryptoLen)
					cryptoLen = currentCryptoLen
				}
				if _, err := buffer.Read(cryptoDataBuf.BytesRange(int32(offset), currentCryptoLen)); err != nil {
					return nil, io.ErrUnexpectedEOF
				}
			case 0x1c:
				if _, err = quicvarint.Read(buffer); err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				length, err := quicvarint.Read(buffer)
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				if _, err := buffer.ReadBytes(int32(length)); err != nil {
					return nil, io.ErrUnexpectedEOF
				}
			default:

				return nil, errNotQuicInitial
			}
		}

		tlsHdr := &ptls.SniffHeader{}
		err = ptls.ReadClientHello(cryptoDataBuf.BytesRange(0, cryptoLen), tlsHdr)
		if err != nil {

			b = restPayload
			continue
		}
		return &SniffHeader{domain: tlsHdr.Domain()}, nil
	}

	return nil, protocol.ErrProtoNeedMoreData
}

func hkdfExpandLabel(hash crypto.Hash, secret, context []byte, label string, length int) []byte {
	b := make([]byte, 3, 3+6+len(label)+1+len(context))
	binary.BigEndian.PutUint16(b, uint16(length))
	b[2] = uint8(6 + len(label))
	b = append(b, []byte("tls13 ")...)
	b = append(b, []byte(label)...)
	b = b[:3+6+len(label)+1]
	b[3+6+len(label)] = uint8(len(context))
	b = append(b, context...)

	out := make([]byte, length)
	n, err := hkdf.Expand(hash.New, secret, b).Read(out)
	if err != nil || n != length {
		panic("quic: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}
