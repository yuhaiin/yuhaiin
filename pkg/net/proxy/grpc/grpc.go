package grpc

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/deadline"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	deadline *deadline.PipeDeadline
}

func newConn(raw stream_conn, laddr, raddr net.Addr, close context.CancelFunc) *conn {
	return &conn{
		raw:   raw,
		raddr: raddr,
		laddr: laddr,
		close: close,
		deadline: deadline.NewPipe(
			deadline.WithReadClose(close),
			deadline.WithWriteClose(func() {
				c, ok := raw.(grpc.ClientStream)
				if ok {
					_ = c.CloseSend()
					return
				}
				close()
			}),
		),
	}
}

func (c *conn) Read(b []byte) (int, error) {
	c.rmux.Lock()
	defer c.rmux.Unlock()

	if c.buf != nil && c.buf.Len() > 0 {
		return c.buf.Read(b)
	}

	data, err := c.raw.Recv()
	if err != nil {
		switch status.Convert(err).Code() {
		case codes.DeadlineExceeded, codes.Canceled:
			return 0, io.EOF
		}
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
	err := c.raw.Send(&wrapperspb.BytesValue{Value: b})
	if err != nil {
		switch status.Convert(err).Code() {
		case codes.DeadlineExceeded, codes.Canceled:
			return 0, io.EOF
		}
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
	c.deadline.SetDeadline(t)
	return nil
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.deadline.SetReadDeadline(t)
	return nil
}
func (c *conn) SetWriteDeadline(t time.Time) error {
	c.deadline.SetWriteDeadline(t)
	return nil
}
