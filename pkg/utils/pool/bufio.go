package pool

import (
	"bufio"
	"bytes"
	"io"
	"math/bits"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var ClosedBufioReader = bufio.NewReaderSize(bytes.NewReader(nil), 10)

var bufioReaderPoolMap syncmap.SyncMap[int, *sync.Pool]

func bufioReaderPool(size int) *sync.Pool {
	if v, ok := bufioReaderPoolMap.Load(size); ok {
		return v
	}

	p := &sync.Pool{New: func() any { return bufio.NewReaderSize(nil, size) }}
	bufioReaderPoolMap.Store(size, p)
	return p
}

func GetBufioReader(r io.Reader, size int) *bufio.Reader {
	xx, ok := r.(*bufioConn)
	if ok && xx.r.Size() >= size {
		return xx.r
	}

	if size == 0 {
		return nil
	}

	l := bits.Len(uint(size)) - 1
	if size != 1<<l {
		size = 1 << (l + 1)
	}
	x := bufioReaderPool(size).Get().(*bufio.Reader)

	x.Reset(r)

	return x
}

func PutBufioReader(b *bufio.Reader) {
	l := bits.Len(uint(b.Size())) - 1
	bufioReaderPool(1 << l).Put(b) //lint:ignore SA6002 ignore temporarily
}

type BufioConn interface {
	net.Conn
	BufioRead(f func(*bufio.Reader) error) error
}

type bufioConn struct {
	r *bufio.Reader
	net.Conn
	mu sync.Mutex
}

func NewBufioConn(r *bufio.Reader, c net.Conn) BufioConn {
	xx, ok := c.(*bufioConn)
	if ok && xx.r == r {
		return xx
	}

	return &bufioConn{r, c, sync.Mutex{}}
}

func NewBufioConnSize(c net.Conn, size int) BufioConn {
	return NewBufioConn(GetBufioReader(c, size), c)
}

func (c *bufioConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.r.Read(b)
}

func (c *bufioConn) Close() error {
	err := c.Conn.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.r
	if r != ClosedBufioReader {
		c.r = ClosedBufioReader
		PutBufioReader(r)
	}
	return err
}

func (c *bufioConn) BufioRead(f func(*bufio.Reader) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return f(c.r)
}
