package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/xtls/xray-core/common"
)

func NewAesDecryptionStream(key []byte, iv []byte) cipher.Stream {
	return NewAesStreamMethod(key, iv, cipher.NewCFBDecrypter)
}

func NewAesEncryptionStream(key []byte, iv []byte) cipher.Stream {
	return NewAesStreamMethod(key, iv, cipher.NewCFBEncrypter)
}

func NewAesStreamMethod(key []byte, iv []byte, f func(cipher.Block, []byte) cipher.Stream) cipher.Stream {
	aesBlock, err := aes.NewCipher(key)
	common.Must(err)
	return f(aesBlock, iv)
}

func NewAesCTRStream(key []byte, iv []byte) cipher.Stream {
	return NewAesStreamMethod(key, iv, cipher.NewCTR)
}

func NewAesGcm(key []byte) cipher.AEAD {
	block := common.Must2(aes.NewCipher(key))
	aead := common.Must2(cipher.NewGCM(block))
	return aead
}
