package netapi

import (
	"io"
	"net"
)

type multipleReaderConn struct {
	net.Conn
	mr io.Reader
}

func NewMultipleReaderConn(c net.Conn, r io.Reader) *multipleReaderConn {
	return &multipleReaderConn{c, r}
}

func (m *multipleReaderConn) Read(b []byte) (int, error) {
	return m.mr.Read(b)
}

func NewPrefixBytesConn(c net.Conn, prefix ...[]byte) net.Conn {
	if len(prefix) == 0 {
		return c
	}

	buf := net.Buffers(prefix)
	return NewMultipleReaderConn(c, io.MultiReader(&buf, c))
}
