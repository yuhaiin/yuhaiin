package yuubinsya

import (
	"crypto/cipher"
	"io"
	"net"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
)

type streamConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

func (c *streamConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *streamConn) Write(b []byte) (int, error) { return c.w.Write(b) }

// NewConn wraps a stream-oriented net.Conn with cipher.
func NewConn(c net.Conn, ciph cipher.AEAD) net.Conn {
	return &streamConn{
		Conn: c,
		r:    shadowaead.NewReader(c, ciph),
		w:    shadowaead.NewWriter(c, ciph),
	}
}
