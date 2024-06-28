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

type Accepter interface {
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
	Payload   []byte
}

func (p *Packet) Clone() *Packet {
	return &Packet{
		Src:       p.Src,
		Dst:       p.Dst,
		WriteBack: p.WriteBack,
		Payload:   pool.Clone(p.Payload),
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

var EmptyDNSServer DNSServer = &emptyHandler{}

type emptyHandler struct{}

func (e *emptyHandler) Close() error                                    { return nil }
func (e *emptyHandler) HandleUDP(context.Context, net.PacketConn) error { return io.EOF }
func (e *emptyHandler) HandleTCP(context.Context, net.Conn) error       { return io.EOF }
func (e *emptyHandler) Do(_ context.Context, b *DNSRawRequest) error {
	pool.PutBytes(b.Question)
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

type ListenerPatch struct {
	Listener
	lis net.Listener
}

func PatchStream(lis net.Listener, inbound Listener) *ListenerPatch {
	return &ListenerPatch{
		Listener: inbound,
		lis:      lis,
	}
}

func (w *ListenerPatch) Stream(ctx context.Context) (net.Listener, error) { return w.lis, nil }

func (w *ListenerPatch) Close() error {
	w.lis.Close()
	return w.Listener.Close()
}

type ChannelServer struct {
	packetChan chan *Packet
	streamChan chan *StreamMeta
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewChannelServer() *ChannelServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &ChannelServer{
		packetChan: make(chan *Packet, 100),
		streamChan: make(chan *StreamMeta, 100),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (s *ChannelServer) AcceptPacket() (*Packet, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case p := <-s.packetChan:
		return p, nil
	}
}

func (s *ChannelServer) AcceptStream() (*StreamMeta, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case p := <-s.streamChan:
		return p, nil
	}
}

func (s *ChannelServer) Close() error {
	s.cancel()
	return nil
}

func (s *ChannelServer) SendPacket(packet *Packet) error {
	packet.Payload = pool.Clone(packet.Payload)
	select {
	case <-s.ctx.Done():
		pool.PutBytes(packet.Payload)
		return s.ctx.Err()
	case s.packetChan <- packet:
		return nil
	}
}

func (s *ChannelServer) SendStream(stream *StreamMeta) error {
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case s.streamChan <- stream:
		return nil
	}
}

func (s *ChannelServer) Context() context.Context { return s.ctx }
