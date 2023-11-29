package netapi

import (
	"io"
	"net"
	"runtime"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
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

var DiscardNetConn net.Conn = &DiscardConn{}

type DiscardConn struct{}

func (*DiscardConn) Read(b []byte) (n int, err error)   { return 0, io.EOF }
func (*DiscardConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (*DiscardConn) Close() error                       { return nil }
func (*DiscardConn) LocalAddr() net.Addr                { return EmptyAddr }
func (*DiscardConn) RemoteAddr() net.Addr               { return EmptyAddr }
func (*DiscardConn) SetDeadline(t time.Time) error      { return nil }
func (*DiscardConn) SetReadDeadline(t time.Time) error  { return nil }
func (*DiscardConn) SetWriteDeadline(t time.Time) error { return nil }

var DiscardNetPacketConn net.PacketConn = &DiscardPacketConn{}

type DiscardPacketConn struct{}

func (*DiscardPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, EmptyAddr, io.EOF
}
func (*DiscardPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}
func (*DiscardPacketConn) Close() error                       { return nil }
func (*DiscardPacketConn) LocalAddr() net.Addr                { return EmptyAddr }
func (*DiscardPacketConn) SetDeadline(t time.Time) error      { return nil }
func (*DiscardPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (*DiscardPacketConn) SetWriteDeadline(t time.Time) error { return nil }

type LogConn struct {
	net.Conn
}

func (l *LogConn) Write(b []byte) (int, error) {
	return l.Conn.Write(b)
}

func (l *LogConn) Read(b []byte) (int, error) {
	n, err := l.Conn.Read(b)
	if err != nil {
		log.Error("tls read failed", "err", err)
	}

	return n, err
}
func (l *LogConn) SetDeadline(t time.Time) error {
	_, file, line, _ := runtime.Caller(3)
	log.Info("set deadline", "time", t, "line", line, "file", file, "time", t)

	return l.Conn.SetDeadline(t)
}

func (l *LogConn) SetReadDeadline(t time.Time) error {
	_, file, line, _ := runtime.Caller(3)
	log.Info("set read deadline", "time", t, "line", line, "file", file, "time", t)

	return l.Conn.SetReadDeadline(t)
}

func (l *LogConn) SetWriteDeadline(t time.Time) error {
	_, file, line, _ := runtime.Caller(4)
	log.Info("set write deadline", "time", t, "line", line, "file", file, "time", t)

	return l.Conn.SetWriteDeadline(t)
}
