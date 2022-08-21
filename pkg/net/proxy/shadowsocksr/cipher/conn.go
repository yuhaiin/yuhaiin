package cipher

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

type Cipher struct {
	key    []byte
	ivSize int
	core.Cipher
}

func NewCipher(method, password string) (*Cipher, error) {
	if method == "none" || method == "dummy" {
		return &Cipher{Cipher: dummy{}}, nil
	}

	if password == "" {
		return nil, fmt.Errorf("password is empty")
	}

	if method == "" {
		method = "rc4-md5"
	}

	ss, ok := streamCipherMethod[method]
	if !ok {
		return nil, fmt.Errorf("unsupported encryption method: %v", method)
	}
	key := ssr.KDF(password, ss.KeySize)
	mi := ss.Creator(key)
	return &Cipher{key, mi.IVSize(), &cipherConn{mi}}, nil
}
func (c *Cipher) IVSize() int  { return c.ivSize }
func (c *Cipher) Key() []byte  { return c.key }
func (c *Cipher) KeySize() int { return len(c.key) }

// dummy cipher does not encrypt
type dummy struct{}

func (dummy) StreamConn(c net.Conn) net.Conn             { return c }
func (dummy) PacketConn(c net.PacketConn) net.PacketConn { return c }

type cipherConn struct{ CipherFactory }

func (c *cipherConn) StreamConn(conn net.Conn) net.Conn { return newStreamConn(conn, c.CipherFactory) }
func (c *cipherConn) PacketConn(conn net.PacketConn) net.PacketConn {
	return newPacketConn(conn, c.CipherFactory)
}

type packetConn struct {
	net.PacketConn
	CipherFactory
}

func newPacketConn(c net.PacketConn, cipherFactory CipherFactory) net.PacketConn {
	return &packetConn{c, cipherFactory}
}

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := utils.GetBytes(utils.DefaultSize)
	defer utils.PutBytes(buf)

	_, err := rand.Read(buf[:p.IVSize()])
	if err != nil {
		return 0, err
	}

	s, err := p.EncryptStream(buf[:p.IVSize()])
	if err != nil {
		return 0, err
	}

	s.XORKeyStream(buf[p.IVSize():], b)

	if _, err = p.PacketConn.WriteTo(buf[:p.IVSize()+len(b)], addr); err != nil {
		return 0, err
	}

	return len(b), nil
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}

	s, err := p.DecryptStream(b[:p.IVSize()])
	if err != nil {
		return 0, nil, err
	}

	s.XORKeyStream(b[p.IVSize():], b[p.IVSize():n])
	n = copy(b, b[p.IVSize():n])

	return n, addr, nil
}

type streamConn struct {
	net.Conn
	cipher CipherFactory

	enc, dec        cipher.Stream
	writeIV, readIV []byte

	buf [utils.DefaultSize / 4]byte
}

func newStreamConn(c net.Conn, cipher CipherFactory) net.Conn {
	return &streamConn{Conn: c, cipher: cipher}
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
		c.dec, err = c.cipher.DecryptStream(c.ReadIV())
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
		c.enc, err = c.cipher.EncryptStream(c.WriteIV())
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
		nr, er := r.Read(c.buf[:])

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
