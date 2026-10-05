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

// GetBufioReader borrows a reader owned by the caller, who must return it with
// PutBufioReader. It never exposes a connection's internal reader: that reader
// can be released by Read or Close independently of the caller's lifetime.
func GetBufioReader(r io.Reader, size int) *bufio.Reader {
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
	// BufioRead serializes the callback with Read and Close. For temporary
	// buffering, the reader and its slices must not escape the callback.
	// Callbacks must not return the connection's reader to a pool.
	BufioRead(f func(*bufio.Reader) error) error
}

type bufioConn struct {
	CloseWriteChecker
	r      *bufio.Reader
	mu     sync.Mutex
	closed bool

	readerSize        int
	releaseAfterDrain bool
	pendingReadErr    error
}

// NewBufioConn takes ownership of r. The caller must not use or pool r after
// passing it to the connection; use BufioRead for synchronized access.
func NewBufioConn(r *bufio.Reader, c net.Conn) BufioConn {
	xx, ok := c.(*bufioConn)
	if ok {
		xx.mu.Lock()
		sameReader := xx.r == r
		if sameReader {
			xx.releaseAfterDrain = false
		}
		xx.mu.Unlock()
		if sameReader {
			return xx
		}
	}

	return &bufioConn{CloseWriteChecker: CloseWriteChecker{c}, r: r, readerSize: r.Size()}
}

// NewBufferedConnSize buffers the initial reads made through BufioRead, then
// returns the reader to its pool once Read drains the pre-read bytes. Use
// NewBufioConnSize for ongoing buffering, such as UDP-over-stream decoding.
func NewBufferedConnSize(c net.Conn, size int) BufioConn {
	return newBufioConnSize(c, size, true)
}

func NewBufioConnSize(c net.Conn, size int) BufioConn {
	return newBufioConnSize(c, size, false)
}

func newBufioConnSize(c net.Conn, size int, releaseAfterDrain bool) *bufioConn {
	if existing, ok := c.(*bufioConn); ok && existing.readerSize >= size {
		existing.mu.Lock()
		existing.releaseAfterDrain = releaseAfterDrain
		existing.mu.Unlock()
		return existing
	}
	conn := NewBufioConn(GetBufioReader(c, size), c).(*bufioConn)
	conn.releaseAfterDrain = releaseAfterDrain
	return conn
}

func (c *bufioConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.EOF
	}
	if c.pendingReadErr != nil {
		err := c.pendingReadErr
		c.pendingReadErr = nil
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}

	if c.r == nil {
		if c.releaseAfterDrain {
			return c.Conn.Read(b)
		}
		c.restoreReader()
	}
	n, err := c.r.Read(b)
	c.releaseDrainedReader()
	return n, err
}

func (c *bufioConn) Close() error {
	err := c.CloseWriteChecker.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return err
	}

	c.closed = true
	c.pendingReadErr = nil

	c.releaseReader()
	return err
}

// The caller holds mu; clearing r before pooling it prevents Close from
// returning a reader that a drained connection has already released.
func (c *bufioConn) releaseReader() {
	if c.r != nil {
		r := c.r
		c.r = nil
		r.Reset(emptyReader{})
		PutBufioReader(r)
	}
}

func (c *bufioConn) releaseDrainedReader() {
	if c.releaseAfterDrain && c.r.Buffered() == 0 {
		// A zero-length read does no I/O and retrieves any error buffered
		// alongside the prefix. Preserve it for the next Read/BufioRead.
		_, c.pendingReadErr = c.r.Read(nil)
		c.releaseReader()
	}
}

// The caller holds mu and has checked that r is nil.
func (c *bufioConn) restoreReader() {
	if c.pendingReadErr == nil {
		c.r = GetBufioReader(c.Conn, c.readerSize)
	} else {
		c.r = GetBufioReader(&errorOnceReader{Reader: c.Conn, err: c.pendingReadErr}, c.readerSize)
		c.pendingReadErr = nil
		// Discard one synthetic byte to seed bufio's pending error without
		// consuming it or touching the connection. Callbacks still observe
		// the original error, even if they only inspect Buffered().
		_, _ = c.r.Discard(1)
	}
}

func (c *bufioConn) BufioRead(f func(*bufio.Reader) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return io.EOF
	}
	if c.r == nil {
		c.restoreReader()
	}
	err := f(c.r)
	c.releaseDrainedReader()
	return err
}

type errorOnceReader struct {
	io.Reader
	err error
}

func (r *errorOnceReader) Read(b []byte) (int, error) {
	if r.err != nil {
		if len(b) == 0 {
			return 0, nil
		}
		b[0] = 0 // Discarded by restoreReader; never exposed to the caller.
		err := r.err
		r.err = nil
		return 1, err
	}
	return r.Reader.Read(b)
}

type emptyReader struct{}

func (e emptyReader) Read([]byte) (int, error) { return 0, io.EOF }
