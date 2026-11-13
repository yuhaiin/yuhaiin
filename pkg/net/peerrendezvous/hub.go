package peerrendezvous

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// A Hub serves a coordinator and the publisher side of every pairing from one
// UDP socket. Publishers are in-process: their rendezvous messages are handled
// directly, and data packets from a registered dialer endpoint are routed to
// that pairing's virtual connection. One forwarded port therefore serves all
// clients.
type Hub struct {
	*Coordinator
	socket net.PacketConn
	// public holds the endpoint peers use to reach this hub, one per IP
	// family: a dual-stack socket serves both.
	public atomic.Pointer[[]netip.AddrPort]
	stun   *stunClient

	mu     sync.Mutex
	conns  map[[16]byte]*hubConn
	closed bool
}

// Sentinel coordinator addresses. They are never used on the network; the
// Socket only needs a coordinator address of the right IP family.
var (
	hubCoordinator4 = netip.MustParseAddrPort("127.0.0.254:9")
	hubCoordinator6 = netip.MustParseAddrPort("[::1]:9")
)

func NewHub(socket net.PacketConn) *Hub {
	h := &Hub{Coordinator: newCoordinator(socket, nil, nil), socket: socket, conns: make(map[[16]byte]*hubConn)}
	h.stun = newSTUNClient(socket)
	h.data = h.dispatch
	h.publisherFor = h.publicFor
	go h.run()
	return h
}

// SetPublic sets the endpoints peers use to reach this hub, at most one per
// IP family. A later endpoint of a family already given is ignored.
func (h *Hub) SetPublic(endpoints ...netip.AddrPort) {
	var public []netip.AddrPort
	for _, endpoint := range endpoints {
		endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
		if endpoint.IsValid() && !slices.ContainsFunc(public, func(p netip.AddrPort) bool { return p.Addr().BitLen() == endpoint.Addr().BitLen() }) {
			public = append(public, endpoint)
		}
	}
	slices.SortFunc(public, func(a, b netip.AddrPort) int { return a.Addr().BitLen() - b.Addr().BitLen() })
	h.public.Store(&public)
}

// Public returns the preferred public endpoint, IPv4 first.
func (h *Hub) Public() netip.AddrPort {
	if public := h.Publics(); len(public) != 0 {
		return public[0]
	}
	return netip.AddrPort{}
}

// Publics returns every public endpoint, IPv4 first.
func (h *Hub) Publics() []netip.AddrPort {
	if p := h.public.Load(); p != nil {
		return slices.Clone(*p)
	}
	return nil
}

// publicFor tells a dialer the hub's endpoint in the dialer's IP family, so
// clients of either family reach the same gateway.
func (h *Hub) publicFor(dialer, registered netip.AddrPort) netip.AddrPort {
	for _, public := range h.Publics() {
		if public.Addr().BitLen() == dialer.Addr().BitLen() {
			return public
		}
	}
	return registered
}

// DiscoverPublic asks a STUN server for the mapped address of the hub's socket.
func (h *Hub) DiscoverPublic(server netip.AddrPort, timeout time.Duration) (netip.AddrPort, error) {
	return h.stun.query(server, timeout)
}

func (h *Hub) LocalAddr() net.Addr { return h.socket.LocalAddr() }

func (h *Hub) Close() error {
	h.mu.Lock()
	h.closed = true
	conns := make([]*hubConn, 0, len(h.conns))
	for _, c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	h.stun.close()
	return h.Coordinator.Close()
}

// Open returns the publisher-side connection for a pairing, creating the
// pairing when needed. A previous connection of the same pairing is closed.
func (h *Hub) Open(key [32]byte) (net.PacketConn, netip.AddrPort, error) {
	public := h.Public()
	if !public.IsValid() {
		return nil, netip.AddrPort{}, errors.New("LAN Link public endpoint is not known")
	}
	coordinator := hubCoordinator4
	if public.Addr().Is6() {
		coordinator = hubCoordinator6
	}
	id := pairID(key)
	c := &hubConn{hub: h, id: id, coordinator: coordinator, in: make(chan hubPacket, 256),
		closed: make(chan struct{}), wake: make(chan struct{}, 1)}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, netip.AddrPort{}, net.ErrClosed
	}
	old := h.conns[id]
	h.conns[id] = c
	h.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	h.AddPair(key)
	return c, coordinator, nil
}

// Remove closes the pairing's connection and forgets the pairing.
func (h *Hub) Remove(key [32]byte) {
	id := pairID(key)
	h.mu.Lock()
	c := h.conns[id]
	delete(h.conns, id)
	h.mu.Unlock()
	h.RemovePair(key)
	if c != nil {
		_ = c.Close()
	}
}

func (h *Hub) dispatch(p []byte, from netip.AddrPort) bool {
	if h.stun.receive(p, from) {
		return true
	}
	id, ok := h.dialerOwner(from, time.Now())
	if !ok {
		return true
	}
	h.mu.Lock()
	c := h.conns[id]
	h.mu.Unlock()
	if c != nil {
		c.deliver(p, net.UDPAddrFromAddrPort(from))
	}
	return true
}

type hubPacket struct {
	data []byte
	from net.Addr
}

type hubConn struct {
	hub         *Hub
	id          [16]byte
	coordinator netip.AddrPort
	in          chan hubPacket
	closed      chan struct{}
	closeOnce   sync.Once
	deadline    atomic.Int64
	wake        chan struct{}
}

func (c *hubConn) deliver(p []byte, from net.Addr) {
	select {
	case c.in <- hubPacket{data: append([]byte(nil), p...), from: from}:
	default: // a slow reader drops packets like a full socket buffer
	}
}

func (c *hubConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		var timer <-chan time.Time
		if d := c.deadline.Load(); d != 0 {
			wait := time.Until(time.Unix(0, d))
			if wait <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(wait)
			defer t.Stop()
			timer = t.C
		}
		select {
		case <-c.closed:
			return 0, nil, net.ErrClosed
		case pkt := <-c.in:
			return copy(p, pkt.data), pkt.from, nil
		case <-timer:
			return 0, nil, os.ErrDeadlineExceeded
		case <-c.wake:
		}
	}
}

func (c *hubConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("LAN Link: unsupported address")
	}
	ap := udp.AddrPort()
	if netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) == c.coordinator {
		if len(p) == messageSize {
			m := message(p)
			if c.hub.handle(&m, len(p), c.hub.Public(), time.Now()) {
				c.deliver(m[:], net.UDPAddrFromAddrPort(c.coordinator))
			}
		}
		return len(p), nil
	}
	return c.hub.socket.WriteTo(p, addr)
}

func (c *hubConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.hub.mu.Lock()
		if c.hub.conns[c.id] == c {
			delete(c.hub.conns, c.id)
		}
		c.hub.mu.Unlock()
	})
	return nil
}

func (c *hubConn) LocalAddr() net.Addr { return c.hub.socket.LocalAddr() }

func (c *hubConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *hubConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.deadline.Store(0)
	} else {
		c.deadline.Store(t.UnixNano())
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}

func (*hubConn) SetWriteDeadline(time.Time) error { return nil }
