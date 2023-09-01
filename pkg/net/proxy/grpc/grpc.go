package grpc

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/wrapperspb"
)

//go:generate protoc --go-grpc_out=. --go-grpc_opt=paths=source_relative chunk.proto

type stream_conn interface {
	Send(*wrapperspb.BytesValue) error
	Recv() (*wrapperspb.BytesValue, error)
}

var _ net.Conn = (*conn)(nil)

type conn struct {
	raw stream_conn

	buf  *bytes.Reader
	rmux sync.Mutex

	raddr net.Addr
	laddr net.Addr

	mu     sync.Mutex
	closed bool
	close  context.CancelFunc

	deadline *time.Timer
}

func (c *conn) Read(b []byte) (int, error) {
	c.rmux.Lock()
	defer c.rmux.Unlock()

	if c.buf != nil && c.buf.Len() > 0 {
		return c.buf.Read(b)
	}

	data, err := c.raw.Recv()
	if err != nil {
		return 0, err
	}

	if c.buf == nil {
		c.buf = bytes.NewReader(data.Value)
	} else {
		c.buf.Reset(data.Value)
	}

	return c.buf.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	if err := c.raw.Send(&wrapperspb.BytesValue{Value: b}); err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.close()
	c.closed = true
	return nil
}
func (c *conn) LocalAddr() net.Addr  { return c.laddr }
func (c *conn) RemoteAddr() net.Addr { return c.raddr }

func (c *conn) SetDeadline(t time.Time) error {
	if c.deadline == nil {
		if !t.IsZero() {
			c.deadline = time.AfterFunc(time.Until(t), func() { c.Close() })
		}
		return nil
	}

	if t.IsZero() {
		c.deadline.Stop()
	} else {
		c.deadline.Reset(time.Until(t))
	}

	return nil
}

func (c *conn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }
