package cipher

import (
	"bytes"
	"crypto/cipher"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

type Cipher struct {
	key    []byte
	cipher CipherCreator
	core.Cipher
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
		return nil, fmt.Errorf("unsupported encryption method: %v", method)
	}
	key := EVPBytesToKey(password, mi.KeySize())

	var conn core.Cipher
	if method == "none" || method == "dummy" {
		conn = &dummy{}
	} else {
		conn = &cipherConn{mi, key}
	}
	return &Cipher{key, mi, conn}, nil
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

func (c *Cipher) IVSize() int {
	return c.cipher.IVSize()
}

func (c *Cipher) Key() []byte {
	return c.key
}

func (c *Cipher) KeySize() int {
	return c.cipher.KeySize()
}

// dummy cipher does not encrypt
type dummy struct{}

func (dummy) StreamConn(c net.Conn) net.Conn             { return c }
func (dummy) PacketConn(c net.PacketConn) net.PacketConn { return c }

type cipherConn struct {
	cipher CipherCreator
	key    []byte
}

func (c *cipherConn) StreamConn(conn net.Conn) net.Conn {
	return newStreamConn(conn, c.cipher, c.key)
}

func (c *cipherConn) PacketConn(conn net.PacketConn) net.PacketConn {
	return newPacketConn(conn, c.cipher, c.key)
}

type packetConn struct {
	net.PacketConn

	key    []byte
	cipher CipherCreator

	buf []byte
}

func newPacketConn(c net.PacketConn, ciph CipherCreator, key []byte) *packetConn {
	return &packetConn{PacketConn: c, key: key, cipher: ciph, buf: utils.GetBytes(utils.DefaultSize)}
}

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	_, err := rand.Read(p.buf[:p.cipher.IVSize()])
	if err != nil {
		return 0, err
	}

	s, err := p.cipher.Encrypter(p.key, p.buf[:p.cipher.IVSize()])
	if err != nil {
		return 0, err
	}

	s.XORKeyStream(p.buf[p.cipher.IVSize():], b)
	n, err := p.PacketConn.WriteTo(p.buf[:p.cipher.IVSize()+len(b)], addr)
	if err != nil {
		return n, err
	}

	return len(b), nil
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	iv := b[:p.cipher.IVSize()]
	s, err := p.cipher.Decrypter(p.key, iv)
	if err != nil {
		return n, addr, err
	}
	dst := make([]byte, n-p.cipher.IVSize())
	s.XORKeyStream(dst, b[p.cipher.IVSize():n])

	n = copy(b, dst)

	return n, addr, nil
}

func (p *packetConn) Close() error {
	utils.PutBytes(p.buf)
	return p.PacketConn.Close()
}

type streamConn struct {
	net.Conn
	key    []byte
	cipher CipherCreator

	enc, dec        cipher.Stream
	writeIV, readIV []byte

	buf []byte
}

func newStreamConn(c net.Conn, ciph CipherCreator, key []byte) *streamConn {
	return &streamConn{Conn: c, key: key, cipher: ciph, buf: utils.GetBytes(2048)}
}

func (c *streamConn) WriteIV() []byte {
	if c.writeIV == nil {
		c.writeIV = make([]byte, c.cipher.IVSize())
		rand.Read(c.writeIV)
	}
	return c.writeIV
}

func (c *streamConn) ReadIV() []byte {
	if c.readIV == nil {
		c.readIV = make([]byte, c.cipher.IVSize())
		io.ReadFull(c.Conn, c.readIV)
	}
	return c.readIV
}

func (c *streamConn) Read(b []byte) (n int, err error) {
	if c.dec == nil {
		c.dec, err = c.cipher.Decrypter(c.key, c.ReadIV())
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

func (c *streamConn) ReadFrom(r io.Reader) (_ int64, err error) {
	if c.enc == nil {
		c.enc, err = c.cipher.Encrypter(c.key, c.WriteIV())
		if err != nil {
			return 0, err
		}

		_, err = c.Conn.Write(c.WriteIV())
		if err != nil {
			return 0, err
		}
	}

	n := int64(0)
	for {
		nr, er := r.Read(c.buf)

		if nr > 0 {
			n += int64(nr)

			c.enc.XORKeyStream(c.buf[:nr], c.buf[:nr])

			_, ew := c.Conn.Write(c.buf[:nr])
			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if !errors.Is(er, io.EOF) {
				err = er
			}
			break
		}
	}

	return n, err
}

func (c *streamConn) Write(b []byte) (int, error) {
	n, err := c.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

func (c *streamConn) Close() error {
	utils.PutBytes(c.buf)
	return c.Conn.Close()
}
