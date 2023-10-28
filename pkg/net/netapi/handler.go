package netapi

import (
	"context"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
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
