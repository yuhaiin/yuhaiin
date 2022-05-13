package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/dgryski/go-camellia"
	"github.com/dgryski/go-idea"
	"github.com/dgryski/go-rc2"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/salsa20/salsa"
)

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

func newCTRStream(block cipher.Block, err error, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newAESCTRStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newCTRStream(block, err, iv, doe)
}

func newOFBStream(block cipher.Block, err error, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newAESOFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newOFBStream(block, err, iv, doe)
}

func newCFBStream(block cipher.Block, err error, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func newAESCFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newCFBStream(block, err, iv, doe)
}

func newDESStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	return newCFBStream(block, err, iv, doe)
}

func newBlowFishStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	aes.NewCipher(key)
	block, err := blowfish.NewCipher(key)
	return newCFBStream(block, err, iv, doe)
}

func newCast5Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	return newCFBStream(block, err, iv, doe)
}

func newRC4MD5Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	rc4key := md5.Sum(append(key, iv...))
	return rc4.NewCipher(rc4key[:])
}

func newChaCha20Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
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
	} else if utils.DefaultSize >= dataSize {
		buf = utils.GetBytes(utils.DefaultSize)
		defer utils.PutBytes(buf)
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

func newSalsa20Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	var c salsaStreamCipher
	copy(c.nonce[:], iv[:8])
	copy(c.key[:], key[:32])

	return &c, nil
}

func newCamelliaStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := camellia.New(key)
	return newCFBStream(block, err, iv, doe)
}

func newIdeaStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := idea.NewCipher(key)
	return newCFBStream(block, err, iv, doe)
}

func newRC2Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := rc2.New(key, 16)
	return newCFBStream(block, err, iv, doe)
}

func newRC4Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	return rc4.NewCipher(key)
}

func newSeedStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	// TODO: SEED block cipher implementation is required
	block, err := rc2.New(key, 16)
	return newCFBStream(block, err, iv, doe)
}

type NoneStream struct {
	cipher.Stream
}

func (*NoneStream) XORKeyStream(dst, src []byte) {
	copy(dst, src)
}

func newNoneStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	return new(NoneStream), nil
}

type CipherCreator interface {
	KeySize() int
	IVSize() int
	Encrypter(key, iv []byte) (cipher.Stream, error)
	Decrypter(key, iv []byte) (cipher.Stream, error)
}
type cipherObserver struct {
	keySize, ivSize int
	stream          func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

func (c cipherObserver) KeySize() int {
	return c.keySize
}

func (c cipherObserver) IVSize() int {
	return c.ivSize
}

func (c cipherObserver) Encrypter(key, iv []byte) (cipher.Stream, error) {
	return c.stream(key, iv, Encrypt)
}

func (c cipherObserver) Decrypter(key, iv []byte) (cipher.Stream, error) {
	return c.stream(key, iv, Decrypt)
}

var streamCipherMethod = map[string]CipherCreator{
	"aes-128-cfb":      cipherObserver{16, 16, newAESCFBStream},
	"aes-192-cfb":      cipherObserver{24, 16, newAESCFBStream},
	"aes-256-cfb":      cipherObserver{32, 16, newAESCFBStream},
	"aes-128-ctr":      cipherObserver{16, 16, newAESCTRStream},
	"aes-192-ctr":      cipherObserver{24, 16, newAESCTRStream},
	"aes-256-ctr":      cipherObserver{32, 16, newAESCTRStream},
	"aes-128-ofb":      cipherObserver{16, 16, newAESOFBStream},
	"aes-192-ofb":      cipherObserver{24, 16, newAESOFBStream},
	"aes-256-ofb":      cipherObserver{32, 16, newAESOFBStream},
	"des-cfb":          cipherObserver{8, 8, newDESStream},
	"bf-cfb":           cipherObserver{16, 8, newBlowFishStream},
	"cast5-cfb":        cipherObserver{16, 8, newCast5Stream},
	"rc4-md5":          cipherObserver{16, 16, newRC4MD5Stream},
	"rc4-md5-6":        cipherObserver{16, 6, newRC4MD5Stream},
	"chacha20":         cipherObserver{32, 8, newChaCha20Stream},
	"chacha20-ietf":    cipherObserver{32, 12, newChaCha20Stream},
	"salsa20":          cipherObserver{32, 8, newSalsa20Stream},
	"camellia-128-cfb": cipherObserver{16, 16, newCamelliaStream},
	"camellia-192-cfb": cipherObserver{24, 16, newCamelliaStream},
	"camellia-256-cfb": cipherObserver{32, 16, newCamelliaStream},
	"idea-cfb":         cipherObserver{16, 8, newIdeaStream},
	"rc2-cfb":          cipherObserver{16, 8, newRC2Stream},
	"seed-cfb":         cipherObserver{16, 8, newSeedStream},
	"rc4":              cipherObserver{16, 0, newRC4Stream},
	"none":             cipherObserver{16, 0, newNoneStream},
}
