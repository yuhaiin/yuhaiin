package netapi

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

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
	net.Listener
}

type Listener interface {
	PacketListener
	StreamListener
	Server
}

type listener struct {
	p PacketListener
	net.Listener
}

func NewListener[T net.Listener](s T, p PacketListener) Listener {
	return &listener{p: p, Listener: s}
}

func (w *listener) SyscallConn() (syscall.RawConn, error) {
	if s, ok := w.Listener.(syscall.Conn); ok {
		return s.SyscallConn()
	}
	return nil, syscall.EOPNOTSUPP
}

func (w *listener) Packet(ctx context.Context) (net.PacketConn, error) {
	if w.p == nil {
		return nil, errors.New("packet listener is nil")
	}

	return w.p.Packet(ctx)
}

func (w *listener) Close() error {
	var err error

	if w.p != nil {
		if er := w.p.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if w.Listener != nil {
		if er := w.Listener.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	return err
}

type Accepter interface {
	Server
	Interface() string
}

type EmptyInterface struct{}

func (EmptyInterface) Interface() string { return "" }

type Handler interface {
	HandleStream(*StreamMeta)
	HandlePacket(*Packet)
	HandlePing(*PingMeta)
}

type ChannelHandler struct {
	ctx    context.Context
	stream chan *StreamMeta
	packet chan *Packet
	ping   chan *PingMeta
}

func NewChannelHandler(ctx context.Context) *ChannelHandler {
	return &ChannelHandler{
		ctx:    ctx,
		stream: make(chan *StreamMeta, system.Procs),
		packet: make(chan *Packet, system.Procs),
		ping:   make(chan *PingMeta, system.Procs),
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

func (h *ChannelHandler) HandlePing(p *PingMeta) {
	select {
	case <-h.ctx.Done():
	case h.ping <- p:
	}
}

func (h *ChannelHandler) Stream() <-chan *StreamMeta { return h.stream }
func (h *ChannelHandler) Packet() <-chan *Packet     { return h.packet }
func (h *ChannelHandler) Ping() <-chan *PingMeta     { return h.ping }

type PingMeta struct {
	Source      net.Addr
	Destination Address
	InboundName string
	WriteBack   func(uint64, error) error
}

type StreamMeta struct {
	Source      net.Addr
	Destination net.Addr
	Inbound     net.Addr
	InboundName string

	Src     net.Conn
	Address Address

	DnsRequest bool
}

type WriteBack interface {
	WriteBack(b []byte, addr net.Addr) (int, error)
}

type WriteBackFunc func(b []byte, addr net.Addr) (int, error)

func (f WriteBackFunc) WriteBack(b []byte, addr net.Addr) (int, error) { return f(b, addr) }

type Packet struct {
	src       net.Addr
	dst       Address
	writeBack WriteBack
	// Payload will set to nil when ref count is negative, get it by [Packet.GetPayload]
	// ! DON'T use Payload directly
	payload     []byte
	MigrateID   uint64
	inboundName string
	dnsRequest  bool

	payloadRef int
	mu         sync.Mutex
}

func WithDNSRequest(b bool) func(*Packet) {
	return func(packet *Packet) {
		packet.dnsRequest = b
	}
}

func WithMigrateID(id uint64) func(*Packet) {
	return func(p *Packet) {
		p.MigrateID = id
	}
}

func WithInboundName(name string) func(*Packet) {
	return func(p *Packet) {
		p.inboundName = name
	}
}

func NewPacket(src net.Addr, dst Address, payload []byte, writeBack WriteBack, opts ...func(*Packet)) *Packet {
	pp := &Packet{
		src:       src,
		dst:       dst,
		writeBack: writeBack,
		payload:   payload,
	}

	for _, v := range opts {
		v(pp)
	}

	return pp
}

func (p *Packet) Src() net.Addr       { return p.src }
func (p *Packet) Dst() Address        { return p.dst }
func (p *Packet) InboundName() string { return p.inboundName }
func (p *Packet) IsDNSRequest() bool  { return p.dnsRequest }

func (p *Packet) GetPayload() []byte {
	p.mu.Lock()
	buf := p.payload
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
			pool.PutBytes(p.payload)
			p.payload = nil
		}
	}

	p.mu.Unlock()
}

func (p *Packet) WriteBack(b []byte, addr net.Addr) (int, error) {
	return p.writeBack.WriteBack(b, addr)
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

type DNSAgent interface {
	Server
	DoStream(context.Context, *DNSStreamRequest) error
	DoDatagram(context.Context, *DNSRawRequest) error
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
		channel: make(chan net.Conn, system.Procs),
	}
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
		_ = conn.Close()
	case c.channel <- conn:
	}
}

func (c *ChannelStreamListener) Close() error {
	c.cancel()
	return nil
}

func (c *ChannelStreamListener) Addr() net.Addr { return c.addr }

type errCountListener struct {
	net.Listener
	errCount atomic.Int64
	maxError int64
}

func NewErrCountListener(l net.Listener, maxError int64) *errCountListener {
	return &errCountListener{
		Listener: l,
		maxError: maxError,
	}
}

func (l *errCountListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil, err
			}

			if l.errCount.Add(1) > l.maxError {
				return nil, err
			}

			continue
		}

		return conn, err
	}
}
