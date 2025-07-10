package shadowaead

import (
	"crypto/rand"
	"io"
	"net"

	yaead "github.com/Asutorufa/yuhaiin/pkg/net/proxy/aead"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks/internal"
)

// payloadSizeMax is the maximum size of payload in bytes.
const payloadSizeMax = 0x3FFF // 16*1024 - 1

type streamConn struct {
	net.Conn
	Cipher
	r io.Reader
	w io.Writer
}

func (c *streamConn) initReader() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	aead, err := c.Decrypter(salt)
	if err != nil {
		return err
	}

	if internal.CheckSalt(salt) {
		return ErrRepeatedSalt
	}

	c.r = yaead.NewReader(c.Conn, make([]byte, aead.NonceSize()), aead, payloadSizeMax)
	return nil
}

func (c *streamConn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *streamConn) initWriter() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	aead, err := c.Encrypter(salt)
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(salt)
	if err != nil {
		return err
	}
	internal.AddSalt(salt)
	c.w = yaead.NewWriter(c.Conn, make([]byte, aead.NonceSize()), aead, payloadSizeMax)
	return nil
}

func (c *streamConn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

// NewConn wraps a stream-oriented net.Conn with cipher.
func NewConn(c net.Conn, ciph Cipher) net.Conn { return &streamConn{Conn: c, Cipher: ciph} }
