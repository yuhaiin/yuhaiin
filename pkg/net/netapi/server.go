package netapi

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

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

type WriteBatchBuf struct {
	Addr    net.Addr
	Payload []byte
}

type WriteBack interface {
	WriteBack(b []byte, addr net.Addr) (int, error)
	// WriteBatch(bufs ...WriteBatchBuf) error
}

type WriteBackFunc func(b []byte, addr net.Addr) (int, error)

func (f WriteBackFunc) WriteBack(b []byte, addr net.Addr) (int, error) { return f(b, addr) }

// func (f WriteBackFunc) WriteBatch(bufs ...WriteBatchBuf) error {
// 	var err error
// 	for _, buf := range bufs {
// 		_, er := f(buf.Payload, buf.Addr)
// 		if er != nil {
// 			err = errors.Join(err, er)
// 		}
// 	}
// 	return err
// }

type Packet struct {
	Src       net.Addr
	Dst       Address
	WriteBack WriteBack
	Payload   []byte
	MigrateID uint64

	payloadRef int
	mu         sync.Mutex
}

func (p *Packet) IncRef() {
	p.mu.Lock()
	p.payloadRef++
	p.mu.Unlock()
}

func (p *Packet) DecRef() {
	p.mu.Lock()
	p.payloadRef--

	// because ref count default is 0, so here no equal
	if p.payloadRef < 0 {
		pool.PutBytes(p.Payload)
	}
	p.mu.Unlock()
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
