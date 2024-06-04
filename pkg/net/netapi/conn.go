package netapi

import (
	"bufio"
	"io"
	"net"
	"runtime"
	"sync"
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
	once    sync.Once
	buffers [][]byte
	net.Conn
}

func (p *prefixBytesConn) Close() error {
	var err error

	p.once.Do(func() {
		err = p.Conn.Close()
		for _, v := range p.buffers {
			pool.PutBytes(v)
		}
	})

	return err
}

func NewPrefixBytesConn(c net.Conn, prefix ...[]byte) net.Conn {
	if len(prefix) == 0 {
		return c
	}

	buf := net.Buffers(prefix)

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

	return NewPrefixBytesConn(c, pool.Clone(data)), nil
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
