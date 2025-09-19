package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/salsa20/salsa"
)

func newAESCTRStream(key, iv []byte, _ bool) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

// TODO: deprecated ofb mode
func newAESOFBStream(key, iv []byte, _ bool) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewOFB(block, iv), nil
}

// TODO: deprecated cfb mode
func newCFBStream(block cipher.Block, err error, iv []byte, decrypt bool) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	if !decrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func newAESCFBStream(key, iv []byte, doe bool) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newCFBStream(block, err, iv, doe)
}

func newChaCha20Stream(key, iv []byte, _ bool) (cipher.Stream, error) {
	return chacha20.NewUnauthenticatedCipher(key, iv)
}

type salsaStreamCipher struct {
	nonce   [8]byte
	key     [32]byte
	counter int
}

func (c *salsaStreamCipher) XORKeyStream(dst, src []byte) {
	var buf []byte
	padLen := c.counter % 64
	dataSize := len(src) + padLen
	if cap(dst) >= dataSize {
		buf = dst[:dataSize]
	} else if pool.DefaultSize >= dataSize {
		buf = pool.GetBytes(pool.DefaultSize)
		defer pool.PutBytes(buf)
		buf = buf[:dataSize]
	} else {
		buf = make([]byte, dataSize)
	}

	var subNonce [16]byte
	copy(subNonce[:], c.nonce[:])
	binary.LittleEndian.PutUint64(subNonce[len(c.nonce):], uint64(c.counter/64))

	// It's difficult to avoid data copy here. src or dst maybe slice from
	// Conn.Read/Write, which can't have padding.
	copy(buf[padLen:], src[:])
	salsa.XORKeyStream(buf, buf, &subNonce, &c.key)
	copy(dst, buf[padLen:])

	c.counter += len(src)
}

func newSalsa20Stream(key, iv []byte, _ bool) (cipher.Stream, error) {
	var c salsaStreamCipher
	copy(c.nonce[:], iv[:8])
	copy(c.key[:], key[:32])

	return &c, nil
}

type NoneStream struct{}

func (NoneStream) XORKeyStream(dst, src []byte)                     { copy(dst, src) }
func newNoneStream(key, iv []byte, doe bool) (cipher.Stream, error) { return new(NoneStream), nil }

type CipherFactory interface {
	IVSize() int
	EncryptStream(iv []byte) (cipher.Stream, error)
	DecryptStream(iv []byte) (cipher.Stream, error)
}
type cipherFactory struct {
	stream func(key, iv []byte, decrypt bool) (cipher.Stream, error)
	key    []byte
	ivSize int
}

func (c cipherFactory) IVSize() int { return c.ivSize }
func (c cipherFactory) EncryptStream(iv []byte) (cipher.Stream, error) {
	return c.stream(c.key, iv, false)
}
func (c cipherFactory) DecryptStream(iv []byte) (cipher.Stream, error) {
	return c.stream(c.key, iv, true)
}

func newCipherObserver(keySize, ivSize int, stream func(key, iv []byte, decrypt bool) (cipher.Stream, error)) struct {
	Creator func(key []byte) CipherFactory
	KeySize int
} {
	return struct {
		Creator func(key []byte) CipherFactory
		KeySize int
	}{
		KeySize: keySize,
		Creator: func(key []byte) CipherFactory {
			return cipherFactory{stream, key, ivSize}
		},
	}
}

var StreamCipherMethod = map[string]struct {
	Creator func(key []byte) CipherFactory
	KeySize int
}{
	"aes-128-cfb":   newCipherObserver(16, 16, newAESCFBStream),
	"aes-192-cfb":   newCipherObserver(24, 16, newAESCFBStream),
	"aes-256-cfb":   newCipherObserver(32, 16, newAESCFBStream),
	"aes-128-ctr":   newCipherObserver(16, 16, newAESCTRStream),
	"aes-192-ctr":   newCipherObserver(24, 16, newAESCTRStream),
	"aes-256-ctr":   newCipherObserver(32, 16, newAESCTRStream),
	"aes-128-ofb":   newCipherObserver(16, 16, newAESOFBStream),
	"aes-192-ofb":   newCipherObserver(24, 16, newAESOFBStream),
	"aes-256-ofb":   newCipherObserver(32, 16, newAESOFBStream),
	"chacha20":      newCipherObserver(chacha20.KeySize, 8, newChaCha20Stream),
	"chacha20-ietf": newCipherObserver(chacha20.KeySize, chacha20.NonceSize, newChaCha20Stream),
	"salsa20":       newCipherObserver(32, 8, newSalsa20Stream),
	"none":          newCipherObserver(16, 0, newNoneStream),
}
