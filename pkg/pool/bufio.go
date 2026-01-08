package pool

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
)

var ClosedBufioReader = bufio.NewReaderSize(emptyReader{}, 10)

var bufioBuffers [32]*sync.Pool

func init() {
	for i := range bufioBuffers {
		bufioBuffers[i] = &sync.Pool{
			New: func() any { return bufio.NewReaderSize(nil, 1<<i) },
		}
	}
}

func GetBufioReader(r io.Reader, size int) *bufio.Reader {
	xx, ok := r.(*bufioConn)
	if ok && xx.r.Size() >= size {
		return xx.r
	}

	if size == 0 {
		return nil
	}

	// Calling this function with a negative length is invalid.
	// make will panic if length is negative, so we don't have to.
	if size > MaxLength || size < 0 {
		return bufio.NewReaderSize(nil, size)
	}

	l := nextLogBase2(uint32(size))
	b := bufioBuffers[l].Get().(*bufio.Reader)

	b.Reset(r)

	return b
}

func PutBufioReader(b *bufio.Reader) {
	if b.Size() > MaxLength || b.Size() <= 0 {
		return
	}

	l := prevLogBase2(uint32(b.Size()))
	bufioBuffers[l].Put(b) //lint:ignore SA6002 ignore temporarily
}

type CloseWrite interface {
	CloseWrite() error
}

type CloseWriteChecker struct {
	net.Conn
}

func (c *CloseWriteChecker) CloseWrite() error {
	x, ok := c.Conn.(CloseWrite)
	if ok {
		return x.CloseWrite()
	}

	return errors.ErrUnsupported
}

type BufioConn interface {
	net.Conn
	BufioRead(f func(*bufio.Reader) error) error
}

type bufioConn struct {
	CloseWriteChecker
	r      *bufio.Reader
	mu     sync.Mutex
	closed bool
}

func NewBufioConn(r *bufio.Reader, c net.Conn) BufioConn {
	xx, ok := c.(*bufioConn)
	if ok && xx.r == r {
		return xx
	}

	return &bufioConn{CloseWriteChecker{c}, r, sync.Mutex{}, false}
}

func NewBufioConnSize(c net.Conn, size int) BufioConn {
	return NewBufioConn(GetBufioReader(c, size), c)
}

func (c *bufioConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.EOF
	}

	return c.r.Read(b)
}

func (c *bufioConn) Close() error {
	err := c.CloseWriteChecker.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return err
	}

	c.closed = true

	r := c.r
	if r != ClosedBufioReader {
		c.r = ClosedBufioReader
		r.Reset(emptyReader{})
		PutBufioReader(r)
	}
	return err
}

func (c *bufioConn) BufioRead(f func(*bufio.Reader) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return io.EOF
	}

	return f(c.r)
}

type emptyReader struct{}

func (e emptyReader) Read([]byte) (int, error) { return 0, io.EOF }
