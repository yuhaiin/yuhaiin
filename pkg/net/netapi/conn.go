package netapi

import (
	"bufio"
	"io"
	"net"
	"runtime"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type multipleReaderTCPConn struct {
	*net.TCPConn
	mr io.Reader
}

func (m *multipleReaderTCPConn) Read(b []byte) (int, error) {
	return m.mr.Read(b)
}

type multipleReaderConn struct {
	net.Conn
	mr io.Reader
}

func NewMultipleReaderConn(c net.Conn, r io.Reader) net.Conn {
	tc, ok := c.(*net.TCPConn)
	if ok {
		return &multipleReaderTCPConn{tc, r}
	}

	return &multipleReaderConn{c, r}
}

func (m *multipleReaderConn) Read(b []byte) (int, error) {
	return m.mr.Read(b)
}

type prefixBytesConn struct {
	buffers []*pool.Bytes
	net.Conn
}

func (p *prefixBytesConn) Close() error {
	err := p.Conn.Close()
	for _, v := range p.buffers {
		pool.PutBytesBuffer(v)
	}
	return err
}

func NewPrefixBytesConn(c net.Conn, prefix ...*pool.Bytes) net.Conn {
	if len(prefix) == 0 {
		return c
	}

	buf := net.Buffers(nil)

	for _, v := range prefix {
		buf = append(buf, v.Bytes())
	}

	conn := NewMultipleReaderConn(c, io.MultiReader(&buf, c))

	return &prefixBytesConn{
		buffers: prefix,
		Conn:    conn,
	}
}

func MergeBufioReaderConn(c net.Conn, r *bufio.Reader) (net.Conn, error) {
	if r.Buffered() <= 0 {
		return c, nil
	}

	data, err := r.Peek(r.Buffered())
	if err != nil {
		return nil, err
	}

	return NewPrefixBytesConn(c, copyBytes(data)), nil
}

func copyBytes(b []byte) *pool.Bytes {
	c := pool.GetBytesBuffer(len(b))
	copy(c.Bytes(), b)
	return c
}

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

func ReadFrom(pc net.PacketConn) (*pool.Bytes, Address, error) {
	b := pool.GetBytesBuffer(pool.MaxSegmentSize)
	n, saddr, err := pc.ReadFrom(b.Bytes())
	if err != nil {
		pool.PutBytesBuffer(b)
		return nil, nil, err
	}
	b.ResetSize(0, n)

	addr, err := ParseSysAddr(saddr)
	if err != nil {
		pool.PutBytesBuffer(b)
		return nil, nil, err
	}

	return b, addr, nil
}
