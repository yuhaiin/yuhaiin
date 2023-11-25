package netapi

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type Server interface {
	io.Closer
}

type Handler interface {
	StreamHandler
	PacketHandler
}

type StreamMeta struct {
	Source      net.Addr
	Destination net.Addr
	Inbound     net.Addr

	Src     net.Conn
	Address Address
}

type StreamHandler interface {
	Stream(ctx context.Context, _ *StreamMeta)
}

type Packet struct {
	Src       net.Addr
	Dst       Address
	WriteBack func(b []byte, addr net.Addr) (int, error)
	Payload   *pool.Bytes
}

type PacketHandler interface {
	Packet(ctx context.Context, pack *Packet)
}

type DNSHandler interface {
	Server
	HandleUDP(context.Context, net.PacketConn) error
	HandleTCP(context.Context, net.Conn) error
	Do(context.Context, *pool.Bytes, func([]byte) error) error
}

var EmptyDNSServer DNSHandler = &emptyHandler{}

type emptyHandler struct{}

func (e *emptyHandler) Close() error                                    { return nil }
func (e *emptyHandler) HandleUDP(context.Context, net.PacketConn) error { return io.EOF }
func (e *emptyHandler) HandleTCP(context.Context, net.Conn) error       { return io.EOF }
func (e *emptyHandler) Do(_ context.Context, b *pool.Bytes, _ func([]byte) error) error {
	pool.PutBytesV2(b)
	return io.EOF
}

type ChannelListener struct {
	mu      sync.RWMutex
	closed  bool
	channel chan net.Conn
	addr    net.Addr
}

func NewChannelListener(addr net.Addr) *ChannelListener {
	return &ChannelListener{
		addr:    addr,
		channel: make(chan net.Conn, system.Procs)}
}

func (c *ChannelListener) Accept() (net.Conn, error) {
	conn, ok := <-c.channel
	if !ok {
		return nil, net.ErrClosed
	}

	return conn, nil
}

func (c *ChannelListener) NewConn(conn net.Conn) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return
	}

	c.channel <- conn
}

func (c *ChannelListener) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.channel)
	return nil
}

func (c *ChannelListener) Addr() net.Addr { return c.addr }
