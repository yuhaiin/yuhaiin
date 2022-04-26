package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"

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

func newCTRStream(block cipher.Block, err error, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newAESCTRStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newCTRStream(block, err, key, iv, doe)
}

func newOFBStream(block cipher.Block, err error, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newAESOFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newOFBStream(block, err, key, iv, doe)
}

func newCFBStream(block cipher.Block, err error, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
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
	return newCFBStream(block, err, key, iv, doe)
}

func newDESStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	return newCFBStream(block, err, key, iv, doe)
}

func newBlowFishStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	aes.NewCipher(key)
	block, err := blowfish.NewCipher(key)
	return newCFBStream(block, err, key, iv, doe)
}

func newCast5Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	return newCFBStream(block, err, key, iv, doe)
}

func newRC4MD5Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
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
	return newCFBStream(block, err, key, iv, doe)
}

func newIdeaStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := idea.NewCipher(key)
	return newCFBStream(block, err, key, iv, doe)
}

func newRC2Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := rc2.New(key, 16)
	return newCFBStream(block, err, key, iv, doe)
}

func newRC4Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	return rc4.NewCipher(key)
}

func newSeedStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	// TODO: SEED block cipher implementation is required
	block, err := rc2.New(key, 16)
	return newCFBStream(block, err, key, iv, doe)
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

type cipherCreator struct {
	keySize int
	ivSize  int
	stream  func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

var streamCipherMethod = map[string]*cipherCreator{
	"aes-128-cfb":      {16, 16, newAESCFBStream},
	"aes-192-cfb":      {24, 16, newAESCFBStream},
	"aes-256-cfb":      {32, 16, newAESCFBStream},
	"aes-128-ctr":      {16, 16, newAESCTRStream},
	"aes-192-ctr":      {24, 16, newAESCTRStream},
	"aes-256-ctr":      {32, 16, newAESCTRStream},
	"aes-128-ofb":      {16, 16, newAESOFBStream},
	"aes-192-ofb":      {24, 16, newAESOFBStream},
	"aes-256-ofb":      {32, 16, newAESOFBStream},
	"des-cfb":          {8, 8, newDESStream},
	"bf-cfb":           {16, 8, newBlowFishStream},
	"cast5-cfb":        {16, 8, newCast5Stream},
	"rc4-md5":          {16, 16, newRC4MD5Stream},
	"rc4-md5-6":        {16, 6, newRC4MD5Stream},
	"chacha20":         {32, 8, newChaCha20Stream},
	"chacha20-ietf":    {32, 12, newChaCha20Stream},
	"salsa20":          {32, 8, newSalsa20Stream},
	"camellia-128-cfb": {16, 16, newCamelliaStream},
	"camellia-192-cfb": {24, 16, newCamelliaStream},
	"camellia-256-cfb": {32, 16, newCamelliaStream},
	"idea-cfb":         {16, 8, newIdeaStream},
	"rc2-cfb":          {16, 8, newRC2Stream},
	"seed-cfb":         {16, 8, newSeedStream},
	"rc4":              {16, 0, newRC4Stream},
	"none":             {16, 0, newNoneStream},
}

type Cipher struct {
	key    []byte
	cipher *cipherCreator

	isNone bool
}

func NewCipher(method, password string) (*Cipher, error) {
	if password == "" {
		return nil, fmt.Errorf("password is empty")
	}
	if method == "" {
		method = "rc4-md5"
	}
	mi, ok := streamCipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	return &Cipher{EVPBytesToKey(password, mi.keySize), mi, method == "none" || method == "dummy"}, nil
}

func (c *Cipher) IVSize() int {
	return c.cipher.ivSize
}

func (c *Cipher) Key() []byte {
	return c.key
}

func (c *Cipher) KeySize() int {
	return c.cipher.keySize
}

func (c *Cipher) Stream(conn net.Conn) net.Conn {
	if c.isNone {
		return conn
	}
	return &streamCipher{key: c.key, cipher: c.cipher, Conn: conn}
}

func (c *Cipher) Packet(conn net.PacketConn) net.PacketConn {
	if c.isNone {
		return conn
	}
	return &PacketCipher{c.cipher, conn, c.key}
}

type PacketCipher struct {
	cipher *cipherCreator
	net.PacketConn
	key []byte
}

func (p *PacketCipher) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := utils.GetBytes(utils.DefaultSize)
	defer utils.PutBytes(buf)
	_, err := rand.Read(buf[:p.cipher.ivSize])
	if err != nil {
		return 0, err
	}

	s, err := p.cipher.stream(p.key, buf[:p.cipher.ivSize], Encrypt)
	if err != nil {
		return 0, err
	}

	s.XORKeyStream(buf[p.cipher.ivSize:], b)
	n, err := p.PacketConn.WriteTo(buf[:p.cipher.ivSize+len(b)], addr)
	if err != nil {
		return n, err
	}

	return len(b), nil
}

func (p *PacketCipher) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	iv := b[:p.cipher.ivSize]
	s, err := p.cipher.stream(p.key, iv, Decrypt)
	if err != nil {
		return n, addr, err
	}
	dst := make([]byte, n-p.cipher.ivSize)
	s.XORKeyStream(dst, b[p.cipher.ivSize:n])

	n = copy(b, dst)

	return n, addr, nil
}

type streamCipher struct {
	net.Conn

	key    []byte
	cipher *cipherCreator

	enc, dec        cipher.Stream
	writeIV, readIV []byte
}

func (c *streamCipher) WriteIV() []byte {
	if c.writeIV == nil {
		c.writeIV = make([]byte, c.cipher.ivSize)
		rand.Read(c.writeIV)
	}
	return c.writeIV
}

func (c *streamCipher) ReadIV() []byte {
	if c.readIV == nil {
		c.readIV = make([]byte, c.cipher.ivSize)
		io.ReadFull(c.Conn, c.readIV)
	}
	return c.readIV
}

func (c *streamCipher) Read(b []byte) (n int, err error) {
	if c.dec == nil {
		c.dec, err = c.cipher.stream(c.key, c.ReadIV(), Decrypt)
		if err != nil {
			return 0, fmt.Errorf("create new decor failed: %w", err)
		}
	}

	n, err = c.Conn.Read(b)
	if err != nil {
		return n, err
	}
	c.dec.XORKeyStream(b, b[:n])
	return n, nil
}

func (c *streamCipher) ReadFrom(r io.Reader) (int64, error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)

	n := int64(0)
	for {
		nr, er := r.Read(buf)
		n += int64(nr)
		_, err := c.Write(buf[:nr])
		if err != nil {
			return n, err
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return n, nil
			}
			return n, er
		}
	}
}

func (c *streamCipher) Write(b []byte) (int, error) {
	var err error
	if c.enc == nil {
		c.enc, err = c.cipher.stream(c.key, c.WriteIV(), Encrypt)
		if err != nil {
			return 0, err
		}

		_, err = c.Conn.Write(c.WriteIV())
		if err != nil {
			return 0, err
		}
	}

	n := 0
	lb := len(b)
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)
	for nw := 0; n < lb && err == nil; n += nw {
		end := n + 2048
		if end > lb {
			end = lb
		}
		c.enc.XORKeyStream(buf, b[n:end])
		nw, err = c.Conn.Write(buf[:end-n])
	}
	return n, err
}

func EVPBytesToKey(password string, keyLen int) (key []byte) {
	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
