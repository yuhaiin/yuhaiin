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

type PrefixBytesConn struct {
	net.Conn
	buffers *buffers
}

func (c *PrefixBytesConn) Close() error {
	c.buffers.Close()
	return c.Conn.Close()
}

func NewPrefixBytesConn(c net.Conn, onPop func([]byte), prefix ...[]byte) net.Conn {
	if len(prefix) == 0 {
		return c
	}

	buf := make([][]byte, len(prefix))
	copy(buf, prefix)

	buffers := &buffers{
		original: prefix,
		buffers:  buf,
		onPop:    onPop,
	}

	conn := NewMultipleReaderConn(c, io.MultiReader(buffers, c))
	return &PrefixBytesConn{conn, buffers}
}

func MergeBufioReaderConn(c net.Conn, r *bufio.Reader) (net.Conn, error) {
	if r.Buffered() <= 0 {
		return c, nil
	}

	data, err := r.Peek(r.Buffered())
	if err != nil {
		return nil, err
	}

	return NewPrefixBytesConn(c, func(b []byte) { pool.PutBytes(b) }, pool.Clone(data)), nil
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

// buffers contains zero or more runs of bytes to write.
//
// On certain machines, for certain types of connections, this is
// optimized into an OS-specific batch write operation (such as
// "writev").
type buffers struct {
	original [][]byte
	buffers  [][]byte
	onPop    func([]byte)
}

// Read from the buffers.
//
// Read implements [io.Reader] for [buffers].
//
// Read modifies the slice v as well as v[i] for 0 <= i < len(v),
// but does not modify v[i][j] for any i, j.
func (v *buffers) Read(p []byte) (n int, err error) {
	for len(p) > 0 && len(v.buffers) > 0 {
		n0 := copy(p, v.buffers[0])
		v.consume(int64(n0))
		p = p[n0:]
		n += n0
	}
	if len(v.buffers) == 0 {
		err = io.EOF
	}
	return
}

func (v *buffers) consume(n int64) {
	for len(v.buffers) > 0 {
		ln0 := int64(len((v.buffers)[0]))
		if ln0 > n {
			(v.buffers)[0] = (v.buffers)[0][n:]
			return
		}
		n -= ln0
		v.buffers[0] = nil
		popData := v.original[0]
		if v.onPop != nil {
			v.onPop(popData)
		}
		v.original = v.original[1:]
		v.buffers = v.buffers[1:]
	}
}

func (v *buffers) Close() {
	x := v.original

	v.original = nil
	v.buffers = nil

	for _, b := range x {
		v.onPop(b)
	}
}
