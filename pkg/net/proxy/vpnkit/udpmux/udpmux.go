// Package udpmux turns one UDP socket into many per-peer net.Conns.
//
// Every datagram-carried protocol here — AnyConnect's DTLS channel, Fortinet's —
// has the same problem: a single bound socket serves every client, so datagrams
// have to be routed to the right session before any key exists to authenticate
// them. Routing by source address is all that is available at that point, and it
// is enough: the session above still has to complete a handshake, so a forged
// address gets an attacker no further than a handshake they cannot finish.
//
// A datagram from a known peer goes to that peer's Conn. One from an unknown
// address is offered to the Start callback, which is the only thing that can
// allocate: it inspects the datagram and either declines or returns the handler
// to run for the new peer.
package udpmux

import (
	"io"
	"net"
	"sync"
	"time"
)

// queueDepth bounds the datagrams buffered for a peer that is not reading.
// Dropping is the right response to a full queue: this is UDP, and the layer
// above already tolerates loss.
const queueDepth = 64

// Mux demultiplexes one UDP socket into per-peer connections.
type Mux struct {
	conn    *net.UDPConn
	maxSize int
	start   func(*net.UDPAddr, []byte) func(*Conn)

	mu     sync.Mutex
	peers  map[string]*Conn
	closed bool
}

// New builds a Mux over conn. maxSize bounds a received datagram. start is
// called for a datagram from an unknown peer: it returns the handler to run in
// its own goroutine for that peer, or nil to ignore the datagram and allocate
// nothing.
func New(conn *net.UDPConn, maxSize int, start func(addr *net.UDPAddr, first []byte) func(*Conn)) *Mux {
	return &Mux{
		conn:    conn,
		maxSize: maxSize,
		start:   start,
		peers:   map[string]*Conn{},
	}
}

// Socket is the underlying socket, for a caller that needs its address.
func (m *Mux) Socket() *net.UDPConn { return m.conn }

// Serve routes datagrams until the socket closes. It blocks.
func (m *Mux) Serve() {
	buf := make([]byte, m.maxSize)
	for {
		n, addr, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			m.shutdown()
			return
		}
		pkt := append([]byte(nil), buf[:n]...)

		m.mu.Lock()
		p, known := m.peers[addr.String()]
		m.mu.Unlock()
		if known {
			p.deliver(pkt)
			continue
		}
		m.maybeStart(addr, pkt)
	}
}

func (m *Mux) maybeStart(addr *net.UDPAddr, pkt []byte) {
	handler := m.start(addr, pkt)
	if handler == nil {
		return
	}
	p := &Conn{m: m, peer: addr, queue: make(chan []byte, queueDepth), done: make(chan struct{})}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.peers[addr.String()] = p
	m.mu.Unlock()

	p.deliver(pkt)
	go handler(p)
}

// Drop forgets a peer and ends its reads. It is idempotent.
func (m *Mux) Drop(p *Conn) {
	m.mu.Lock()
	if m.peers[p.peer.String()] == p {
		delete(m.peers, p.peer.String())
	}
	m.mu.Unlock()
	p.stop()
}

func (m *Mux) shutdown() {
	m.mu.Lock()
	m.closed = true
	peers := make([]*Conn, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	m.peers = map[string]*Conn{}
	m.mu.Unlock()
	for _, p := range peers {
		p.stop()
	}
}

// Close closes the socket, which ends Serve and every peer Conn.
func (m *Mux) Close() error { return m.conn.Close() }

// Conn is a net.Conn for one peer over the shared socket: reads come from the
// demultiplexer's queue, writes go straight out addressed to that peer.
type Conn struct {
	m    *Mux
	peer *net.UDPAddr

	queue chan []byte
	// done is closed when the peer is dropped, and it -- not closing queue -- is
	// what ends a Read.
	//
	// Serve looks a peer up under the Mux lock and then delivers outside it, so a
	// Drop can land in between: closing queue would then be a close racing a
	// send, which is a "send on closed channel" panic taking the whole gateway
	// down because one peer went away. Leaving queue open costs the buffered
	// datagrams a GC cycle and nothing else.
	done      chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	deadline time.Time
}

// deliver hands a datagram to the peer, dropping it if the peer is not keeping
// up rather than blocking the shared read loop.
func (p *Conn) deliver(pkt []byte) {
	select {
	case p.queue <- pkt:
	default:
	}
}

func (p *Conn) Read(b []byte) (int, error) {
	p.mu.Lock()
	deadline := p.deadline
	p.mu.Unlock()

	var timeout <-chan time.Time
	if !deadline.IsZero() {
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case pkt := <-p.queue:
		return copy(b, pkt), nil
	case <-p.done:
		return 0, io.EOF
	case <-timeout:
		return 0, ErrTimeout{}
	}
}

func (p *Conn) Write(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	default:
	}
	return p.m.conn.WriteToUDP(b, p.peer)
}

func (p *Conn) Close() error {
	p.m.Drop(p)
	return nil
}

// stop ends the peer's reads and refuses its writes. It is idempotent, because
// both Drop and the Mux shutdown reach it and either may be first.
func (p *Conn) stop() {
	p.closeOnce.Do(func() { close(p.done) })
}

func (p *Conn) LocalAddr() net.Addr  { return p.m.conn.LocalAddr() }
func (p *Conn) RemoteAddr() net.Addr { return p.peer }

func (p *Conn) SetDeadline(t time.Time) error    { return p.SetReadDeadline(t) }
func (p *Conn) SetWriteDeadline(time.Time) error { return nil }
func (p *Conn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	return nil
}

// ErrTimeout is a net.Error the DTLS retransmission logic recognises as a
// timeout rather than a fatal read error.
type ErrTimeout struct{}

func (ErrTimeout) Error() string   { return "udpmux: read timeout" }
func (ErrTimeout) Timeout() bool   { return true }
func (ErrTimeout) Temporary() bool { return true }

var (
	_ net.Conn  = (*Conn)(nil)
	_ net.Error = ErrTimeout{}
)
