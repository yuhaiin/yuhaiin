package trafficcontrol

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// WrapConn charges the client-facing stream once, before either ordinary relay
// or HTTP interception takes ownership. resolve reads the existing route's
// identity; it must never perform another route match. Policy changes affect
// subsequent operations on established connections as well as new streams.
func WrapConn(ctx context.Context, conn net.Conn, resolve func() Policy) net.Conn {
	return wrapConn(ctx, conn, resolve, Upload, nil)
}

// WrapOutboundConn uses the same live policy and deadline implementation as
// inbound streams, with reads charged to download and writes to upload.
func WrapOutboundConn(ctx context.Context, conn net.Conn, resolve func() Policy, onWait func()) net.Conn {
	return wrapConn(ctx, conn, resolve, Download, onWait)
}

func wrapConn(ctx context.Context, conn net.Conn, resolve func() Policy, read Direction, onWait func()) net.Conn {
	ctx, cancel := context.WithCancel(ctx)
	c := &shapedConn{Conn: conn, ctx: ctx, resolve: resolve, cancel: cancel, readDirection: read, onWait: onWait}
	c.stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
	return c
}

type shapedConn struct {
	onWait                      func()
	readDirection               Direction
	cancel                      context.CancelFunc
	readMu                      sync.Mutex
	pending                     []byte
	pendingErr                  error
	readDeadline, writeDeadline streamDeadline
	net.Conn
	ctx     context.Context
	resolve func() Policy
	stop    func() bool
}

func (c *shapedConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.read(p)
}
func (c *shapedConn) read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) > 0 {
		return c.readPending(p)
	}
	if c.resolve().Enabled(c.readDirection) {
		p = p[:min(len(p), 16<<10)]
	}
	n, err := c.Conn.Read(p)
	return c.finishRead(p[:n], err)
}
func (c *shapedConn) finishRead(data []byte, readErr error) (int, error) {
	n, err := c.paceRead(data, readErr)
	// A deadline is recoverable: the caller may extend it and continue reading.
	// Keep only the unadmitted tail of this one read, never read another buffer
	// until it is delivered, and preserve a deferred EOF/error with that tail.
	if errors.Is(err, os.ErrDeadlineExceeded) && n < len(data) {
		c.pending = bytes.Clone(data[n:])
		c.pendingErr = readErr
	}
	return n, err
}
func (c *shapedConn) readPending(p []byte) (int, error) {
	n := copy(p, c.pending)
	var readErr error
	if n == len(c.pending) {
		readErr = c.pendingErr
	}
	paced, err := c.paceRead(p[:n], readErr)
	c.pending = c.pending[paced:]
	if len(c.pending) == 0 {
		c.pending = nil
		c.pendingErr = nil
	}
	return paced, err
}

func (c *shapedConn) paceRead(data []byte, readErr error) (int, error) {
	policy := c.resolve()
	if !policy.Enabled(c.readDirection) {
		policy.admitted(c.readDirection, len(data))
		return len(data), readErr
	}
	n, err := (ShapedWriter{Writer: io.Discard, Context: c.ctx, Policy: policy, Direction: c.readDirection, deadline: &c.readDeadline, localErrors: c.readDirection == Download, onWait: c.onWait}).Write(data)
	if err != nil {
		return n, err
	}
	return n, readErr
}

// Preserve buffer lending from protocol/stack connections: idle streams must
// not pin an extra copy buffer merely because shaping is configured later.
func (c *shapedConn) ReadWithBuffer(getBuffer func() []byte) ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.pending) > 0 {
		data := getBuffer()
		n, err := c.readPending(data)
		return data[:n], err
	}
	if reader, ok := c.Conn.(interface {
		ReadWithBuffer(func() []byte) ([]byte, error)
	}); ok {
		get := getBuffer
		if c.resolve().Enabled(c.readDirection) {
			get = func() []byte { data := getBuffer(); return data[:min(len(data), 16<<10)] }
		}
		data, err := reader.ReadWithBuffer(get)
		n, err := c.finishRead(data, err)
		return data[:n], err
	}
	data := getBuffer()
	n, err := c.read(data)
	return data[:n], err
}

func (c *shapedConn) Write(p []byte) (int, error) {
	policy := c.resolve()
	direction := Download
	if c.readDirection == Download {
		direction = Upload
	}
	if !policy.Enabled(direction) {
		n, err := c.Conn.Write(p)
		policy.admitted(direction, n)
		return n, err
	}
	return (ShapedWriter{Writer: c.Conn, Context: c.ctx, Policy: policy, Direction: direction, deadline: &c.writeDeadline, localErrors: c.readDirection == Download, onWait: c.onWait}).Write(p)
}
func (c *shapedConn) Close() error { c.stop(); c.cancel(); return c.Conn.Close() }
func (c *shapedConn) CloseRead() error {
	c.readDeadline.close()
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return errors.ErrUnsupported
}
func (c *shapedConn) CloseWrite() error {
	c.writeDeadline.close()
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *shapedConn) SetDeadline(at time.Time) error {
	c.readDeadline.set(at)
	c.writeDeadline.set(at)
	return c.Conn.SetDeadline(at)
}
func (c *shapedConn) SetReadDeadline(at time.Time) error {
	c.readDeadline.set(at)
	return c.Conn.SetReadDeadline(at)
}
func (c *shapedConn) SetWriteDeadline(at time.Time) error {
	c.writeDeadline.set(at)
	return c.Conn.SetWriteDeadline(at)
}
