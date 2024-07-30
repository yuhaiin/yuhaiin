package netapi

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type Server interface {
	io.Closer
}

type PacketListener interface {
	Server
	Packet(context.Context) (net.PacketConn, error)
}

type StreamListener interface {
	Server
	Stream(context.Context) (net.Listener, error)
}

type Listener interface {
	PacketListener
	StreamListener
	Server
}

type listener struct {
	p PacketListener
	s net.Listener
}

func NewListener(s net.Listener, p PacketListener) Listener            { return &listener{p: p, s: s} }
func (w *listener) Packet(ctx context.Context) (net.PacketConn, error) { return w.p.Packet(ctx) }
func (w *listener) Stream(ctx context.Context) (net.Listener, error)   { return w.s, nil }
func (w *listener) Close() error {
	var err error

	if er := w.p.Close(); er != nil {
		err = errors.Join(err, er)
	}

	if er := w.s.Close(); er != nil {
		err = errors.Join(err, er)
	}

	return err
}

type Accepter interface{ Server }

type Handler interface {
	HandleStream(*StreamMeta)
	HandlePacket(*Packet)
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
	Payload   []byte
	MigrateID uint64
}

func (p *Packet) Clone() *Packet {
	return &Packet{
		Src:       p.Src,
		Dst:       p.Dst,
		WriteBack: p.WriteBack,
		Payload:   pool.Clone(p.Payload),
		MigrateID: p.MigrateID,
	}
}

type DNSRawRequest struct {
	WriteBack func([]byte) error
	Question  []byte
	Stream    bool
}

type DNSServer interface {
	Server
	HandleUDP(context.Context, net.PacketConn) error
	HandleTCP(context.Context, net.Conn) error
	Do(context.Context, *DNSRawRequest) error
}

var EmptyDNSServer DNSServer = &emptyDNSServer{}

type emptyDNSServer struct{}

func (e *emptyDNSServer) Close() error                                    { return nil }
func (e *emptyDNSServer) HandleUDP(context.Context, net.PacketConn) error { return io.EOF }
func (e *emptyDNSServer) HandleTCP(context.Context, net.Conn) error       { return io.EOF }
func (e *emptyDNSServer) Do(_ context.Context, b *DNSRawRequest) error {
	pool.PutBytes(b.Question)
	return io.EOF
}

type ChannelStreamListener struct {
	ctx     context.Context
	cancel  context.CancelFunc
	channel chan net.Conn
	addr    net.Addr
}

func NewChannelStreamListener(addr net.Addr) *ChannelStreamListener {
	ctx, cancel := context.WithCancel(context.Background())
	return &ChannelStreamListener{
		addr:    addr,
		ctx:     ctx,
		cancel:  cancel,
		channel: make(chan net.Conn, system.Procs)}
}

func (c *ChannelStreamListener) Accept() (net.Conn, error) {
	select {
	case <-c.ctx.Done():
		return nil, c.ctx.Err()

	case conn := <-c.channel:
		return conn, nil
	}
}

func (c *ChannelStreamListener) NewConn(conn net.Conn) {
	select {
	case <-c.ctx.Done():
		conn.Close()
	case c.channel <- conn:
	}
}

func (c *ChannelStreamListener) Close() error {
	c.cancel()
	return nil
}

func (c *ChannelStreamListener) Addr() net.Addr { return c.addr }
