package netapi

import (
	"context"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type Server interface {
	io.Closer
}

type Listener interface {
	Stream(context.Context) (net.Listener, error)
	Packet(context.Context) (net.PacketConn, error)
	Server
}

type ProtocolServer interface {
	Server
	AcceptStream() (*StreamMeta, error)
	AcceptPacket() (*Packet, error)
}

type StreamMeta struct {
	Source      net.Addr
	Destination net.Addr
	Inbound     net.Addr

	Src     net.Conn
	Address Address
}

type WriteBack func(b []byte, addr net.Addr) (int, error)

type Packet struct {
	Src       net.Addr
	Dst       Address
	WriteBack WriteBack
	Payload   *pool.Bytes
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
	ctx     context.Context
	cancel  context.CancelFunc
	channel chan net.Conn
	addr    net.Addr
}

func NewChannelListener(addr net.Addr) *ChannelListener {
	ctx, cancel := context.WithCancel(context.Background())
	return &ChannelListener{
		addr:    addr,
		ctx:     ctx,
		cancel:  cancel,
		channel: make(chan net.Conn, system.Procs)}
}

func (c *ChannelListener) Accept() (net.Conn, error) {
	select {
	case <-c.ctx.Done():
		return nil, c.ctx.Err()

	case conn := <-c.channel:
		return conn, nil
	}
}

func (c *ChannelListener) NewConn(conn net.Conn) {
	select {
	case <-c.ctx.Done():
		conn.Close()
	case c.channel <- conn:
	}

}

func (c *ChannelListener) Close() error {
	c.cancel()
	return nil
}

func (c *ChannelListener) Addr() net.Addr { return c.addr }
