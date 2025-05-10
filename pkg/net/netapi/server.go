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

	if w.p != nil {
		if er := w.p.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if w.s != nil {
		if er := w.s.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	return err
}

type Accepter interface{ Server }

type Handler interface {
	HandleStream(*StreamMeta)
	HandlePacket(*Packet)
}

type ChannelHandler struct {
	ctx    context.Context
	stream chan *StreamMeta
	packet chan *Packet
}

func NewChannelHandler(ctx context.Context) *ChannelHandler {
	return &ChannelHandler{
		ctx:    ctx,
		stream: make(chan *StreamMeta, system.Procs),
		packet: make(chan *Packet, system.Procs),
	}
}

func (h *ChannelHandler) HandleStream(s *StreamMeta) {
	select {
	case <-h.ctx.Done():
	case h.stream <- s:
	}
}
func (h *ChannelHandler) HandlePacket(p *Packet) {
	select {
	case <-h.ctx.Done():
	case h.packet <- p:
	}
}

func (h *ChannelHandler) Stream() <-chan *StreamMeta { return h.stream }
func (h *ChannelHandler) Packet() <-chan *Packet     { return h.packet }

type StreamMeta struct {
	Source      net.Addr
	Destination net.Addr
	Inbound     net.Addr

	Src     net.Conn
	Address Address
}

type WriteBack interface {
	WriteBack(b []byte, addr net.Addr) (int, error)
}

type WriteBackFunc func(b []byte, addr net.Addr) (int, error)

func (f WriteBackFunc) WriteBack(b []byte, addr net.Addr) (int, error) { return f(b, addr) }

type Packet struct {
	Src       net.Addr
	Dst       Address
	WriteBack WriteBack
	// Payload will set to nil when ref count is negative, get it by [Packet.GetPayload]
	// ! DON'T use Payload directly
	Payload   []byte
	MigrateID uint64

	payloadRef int
	mu         sync.Mutex
}

func (p *Packet) GetPayload() []byte {
	p.mu.Lock()
	buf := p.Payload
	p.mu.Unlock()
	return buf
}

func (p *Packet) IncRef() {
	p.mu.Lock()

	// the buf is already released when ref count is negative
	if p.payloadRef >= 0 {
		p.payloadRef++
	}

	p.mu.Unlock()
}

func (p *Packet) DecRef() {
	p.mu.Lock()

	// the buf is already released when ref count is negative
	if p.payloadRef >= 0 {
		p.payloadRef--

		// because ref count default is 0, so here no equal
		if p.payloadRef < 0 {
			pool.PutBytes(p.Payload)
			p.Payload = nil
		}
	}

	p.mu.Unlock()
}

type DNSRawRequest struct {
	WriteBack   func([]byte) error
	Question    *Packet
	Stream      bool
	ForceFakeIP bool
}

type DNSStreamRequest struct {
	Conn        net.Conn
	ForceFakeIP bool
}
type DNSServer interface {
	Server
	DoStream(context.Context, *DNSStreamRequest) error
	Do(context.Context, *DNSRawRequest) error
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
