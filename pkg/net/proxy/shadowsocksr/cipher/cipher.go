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

var errEmptyPassword = errors.New("empty key")

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

func newChacha20IETFStream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
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

type cipherInfo struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

var streamCipherMethod = map[string]*cipherInfo{
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
	"chacha20-ietf":    {32, 12, newChacha20IETFStream},
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

func CheckCipherMethod(method string) error {
	if method == "" {
		method = "rc4-md5"
	}
	_, ok := streamCipherMethod[method]
	if !ok {
		return errors.New("Unsupported encryption method: " + method)
	}
	return nil
}

type Cipher struct {
	key  []byte
	info *cipherInfo
}

func NewCipher(method, password string) (*Cipher, error) {
	if password == "" {
		return nil, errEmptyPassword
	}
	if method == "" {
		method = "rc4-md5"
	}
	mi, ok := streamCipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	key := EVPBytesToKey(password, mi.keyLen)
	return &Cipher{key, mi}, nil
}

func (c *Cipher) IVLen() int {
	return c.info.ivLen
}

func (c *Cipher) Key() []byte {
	return c.key
}

func (c *Cipher) KeyLen() int {
	return c.info.keyLen
}

func (c *Cipher) StreamCipher(conn net.Conn) *StreamCipher {
	return &StreamCipher{
		key:  c.key,
		info: c.info,
		Conn: conn,
	}
}

func (c *Cipher) PacketCipher(conn net.PacketConn) net.PacketConn {
	return &PacketCipher{
		key:        c.key,
		info:       c.info,
		PacketConn: conn,
	}
}

type PacketCipher struct {
	info *cipherInfo
	net.PacketConn
	key []byte
}

func (p *PacketCipher) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := utils.GetBytes(utils.DefaultSize)
	defer utils.PutBytes(buf)
	_, err := rand.Read(buf[:p.info.ivLen])
	if err != nil {
		return 0, err
	}

	s, err := p.info.newStream(p.key, buf[:p.info.ivLen], Encrypt)
	if err != nil {
		return 0, err
	}

	s.XORKeyStream(buf[p.info.ivLen:], b)
	n, err := p.PacketConn.WriteTo(buf[:p.info.ivLen+len(b)], addr)
	if err != nil {
		return n, err
	}

	// defer log.Println("PacketCipher.WriteTo", addr.String(), n)
	return len(b), nil
}

func (p *PacketCipher) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	// log.Println("PacketCipher.ReadFrom", addr.String(), n)
	iv := b[:p.info.ivLen]
	s, err := p.info.newStream(p.key, iv, Decrypt)
	if err != nil {
		return n, addr, err
	}
	dst := make([]byte, n-p.info.ivLen)
	s.XORKeyStream(dst, b[p.info.ivLen:n])

	n = copy(b, dst)

	return n, addr, nil
}

type StreamCipher struct {
	enc     cipher.Stream
	dec     cipher.Stream
	key     []byte
	info    *cipherInfo
	writeIv []byte
	readIV  []byte
	net.Conn
}

// NewStreamCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewStreamCipher(conn net.Conn, method, password string) (c *StreamCipher, err error) {
	if password == "" {
		return nil, errEmptyPassword
	}
	if method == "" {
		method = "rc4-md5"
	}
	mi, ok := streamCipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	key := EVPBytesToKey(password, mi.keyLen)

	c = &StreamCipher{key: key, info: mi, Conn: conn}

	return c, nil
}

func (c *StreamCipher) InitDecrypt(iv []byte) (err error) {
	c.readIV = iv
	c.dec, err = c.info.newStream(c.key, iv, Decrypt)
	return
}

// Initializes the block cipher with CFB mode, returns IV.
func (c *StreamCipher) InitEncrypt() (iv []byte, err error) {
	c.enc, err = c.info.newStream(c.key, c.WriteIV(), Encrypt)
	return c.WriteIV(), err
}

func (c *StreamCipher) Encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c *StreamCipher) Decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

func (c *StreamCipher) Key() []byte {
	return c.key
}

func (c *StreamCipher) WriteIV() []byte {
	if c.writeIv == nil {
		c.writeIv = make([]byte, c.info.ivLen)
		rand.Read(c.writeIv)
	}
	return c.writeIv
}

func (c *StreamCipher) InfoIVLen() int {
	return c.info.ivLen
}

func (c *StreamCipher) InfoKeyLen() int {
	return c.info.keyLen
}

// var read = int64(0)

func (c *StreamCipher) Read(b []byte) (int, error) {
	if c.dec == nil {
		z := utils.GetBytes(c.InfoIVLen())
		defer utils.PutBytes(z)

		// c.Conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		// atomic.AddInt64(&read, 1)
		// log.Println("----------start read----------", atomic.LoadInt64(&read))
		_, err := io.ReadFull(c.Conn, z[:c.InfoIVLen()])
		if err != nil {
			// atomic.AddInt64(&read, -1)
			// log.Println("----------end read----------", atomic.LoadInt64(&read), err)
			// logasfmt.Println("read error", err)
			return 0, err
		}
		// c.Conn.SetReadDeadline(time.Time{})
		// atomic.AddInt64(&read, -1)
		// log.Println("----------read iv----------", atomic.LoadInt64(&read))

		copy(c.readIV, z)
		c.dec, err = c.info.newStream(c.key, z[:c.InfoIVLen()], Decrypt)
		if err != nil {
			return 0, fmt.Errorf("create new decor failed: %w", err)
		}
	}

	n, err := c.Conn.Read(b)
	if err != nil {
		return n, err
	}
	// log.Println("read:", n)
	c.dec.XORKeyStream(b, b[:n])
	// log.Println(len(b))
	return n, nil
}

func (c *StreamCipher) ReadFrom(r io.Reader) (int64, error) {
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

func (c *StreamCipher) Write(b []byte) (int, error) {
	var err error
	if c.enc == nil {
		c.enc, err = c.info.newStream(c.key, c.WriteIV(), Encrypt)
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
	const md5Len = 16

	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, MD5Sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], MD5Sum(d))
	}
	return m[:keyLen]
}

func MD5Sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}
