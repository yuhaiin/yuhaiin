package yuubinsya

import (
	"crypto/cipher"
	"io"
	"net"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"golang.org/x/crypto/chacha20poly1305"
)

type Aead interface {
	New([]byte) (cipher.AEAD, error)
	KeySize() int
	Name() []byte
}

var Chacha20poly1305 = chacha20poly1305Aead{}

type chacha20poly1305Aead struct{}

func (chacha20poly1305Aead) New(key []byte) (cipher.AEAD, error) { return chacha20poly1305.New(key) }
func (chacha20poly1305Aead) KeySize() int                        { return chacha20poly1305.KeySize }
func (chacha20poly1305Aead) Name() []byte                        { return []byte("chacha20poly1305-key") }

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
