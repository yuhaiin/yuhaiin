package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

// ListenPacketEgress opens a listen-style UDP socket for traffic that may go
// to many destinations (a direct UDP relay).
//
// Where protection needs an interface binding (macOS, Windows, Linux without
// SO_MARK) one bound socket cannot reach destinations behind other
// interfaces. The returned conn then keeps one socket per egress interface,
// chosen per datagram from the destination, so a LAN on a second NIC and the
// Internet on the first both work from one flow. Elsewhere it is an ordinary
// socket that the kernel routes per packet.
func ListenPacketEgress(ctx context.Context, network string, opts ...func(*Options)) (net.PacketConn, error) {
	base := &Options{}
	for _, o := range opts {
		o(base)
	}
	if !perDestinationEgress(ctx, base) {
		return ListenPacketWithOptions(ctx, network, "", base)
	}
	return newEgressPacketConn(ctx, network, *base, func(ctx context.Context, network string, opts *Options) (net.PacketConn, error) {
		return ListenPacketWithOptions(ctx, network, "", opts)
	})
}

func contextBindInterface(ctx context.Context) string {
	return netapi.GetContext(ctx).ConnOptions().BindInterface()
}

func perDestinationEgress(ctx context.Context, opts *Options) bool {
	if explicitInterface(contextBindInterface(ctx), opts.InterfaceName) != "" {
		return false
	}
	return ownTunActive() && bindsAutomatically(protectorTrusted())
}

type listenFunc func(ctx context.Context, network string, opts *Options) (net.PacketConn, error)

type datagram struct {
	b    []byte
	from net.Addr
	err  error
	buf  *[]byte
}

type egressSocket struct {
	iface string
	conn  net.PacketConn
}

// egressPacketConn multiplexes one socket per egress interface behind a
// single PacketConn. Sockets are created on first use and live until Close;
// an invalidated socket (its network went away) is dropped and recreated.
type egressPacketConn struct {
	ctx     context.Context
	network string
	base    Options
	listen  listenFunc

	mu      sync.Mutex
	sockets map[string]*egressSocket
	primary *egressSocket
	closed  bool

	recv   chan datagram
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
	reader sync.Mutex // serializes ReadFrom callers

	deadline struct {
		sync.Mutex
		read  time.Time
		write time.Time
		wake  chan struct{}
	}
	recovery func()
}

func newEgressPacketConn(ctx context.Context, network string, base Options, listen listenFunc) (*egressPacketConn, error) {
	c := &egressPacketConn{
		ctx:     context.WithoutCancel(ctx),
		network: network,
		base:    base,
		listen:  listen,
		sockets: map[string]*egressSocket{},
		recv:    make(chan datagram, 64),
		done:    make(chan struct{}),
	}
	c.deadline.wake = make(chan struct{})
	var first netip.Addr
	if base.PacketConnHintAddress != nil {
		first = localIP(base.PacketConnHintAddress)
	}
	s, err := c.socketFor(first)
	if err != nil {
		return nil, err
	}
	c.primary = s
	return c, nil
}

// socketFor returns the socket for dst's egress interface, opening it on
// first use.
func (c *egressPacketConn) socketFor(dst netip.Addr) (*egressSocket, error) {
	iface, err := resolveEgress("", dst, protectorTrusted())
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if s, ok := c.sockets[iface]; ok && !invalidated(s.conn) {
		return s, nil
	} else if ok {
		delete(c.sockets, iface)
		_ = s.conn.Close()
	}
	opts := c.base
	opts.InterfaceName = iface
	opts.PacketConnHintAddress = nil
	if dst.IsValid() {
		opts.PacketConnHintAddress = net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 0))
	}
	conn, err := c.listen(c.ctx, c.network, &opts)
	if err != nil {
		return nil, err
	}
	s := &egressSocket{iface: iface, conn: conn}
	c.sockets[iface] = s
	if c.recovery != nil {
		if r, ok := conn.(interface{ SetNetworkRecovery(func()) }); ok {
			r.SetNetworkRecovery(c.recovery)
		}
	}
	c.wg.Add(1)
	go c.read(s)
	return s, nil
}

func invalidated(conn net.PacketConn) bool {
	if n, ok := conn.(interface{ NetworkInvalidated() bool }); ok {
		return n.NetworkInvalidated()
	}
	return false
}

var datagramPool = sync.Pool{New: func() any { b := make([]byte, 65535); return &b }}

func (c *egressPacketConn) read(s *egressSocket) {
	defer c.wg.Done()
	for {
		buf := datagramPool.Get().(*[]byte)
		n, from, err := s.conn.ReadFrom(*buf)
		if err != nil && isTimeout(err) {
			// Inner deadlines are never set; ignore spurious timeouts.
			datagramPool.Put(buf)
			continue
		}
		if err != nil && s != c.primary {
			// A secondary egress went away (network change, close). Drop
			// it; the next datagram to that egress opens a new socket.
			datagramPool.Put(buf)
			c.mu.Lock()
			if c.sockets[s.iface] == s {
				delete(c.sockets, s.iface)
			}
			c.mu.Unlock()
			_ = s.conn.Close()
			return
		}
		d := datagram{b: (*buf)[:n], from: from, err: err, buf: buf}
		select {
		case c.recv <- d:
		case <-c.done:
			datagramPool.Put(buf)
			return
		}
		if err != nil {
			return
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (c *egressPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.reader.Lock()
	defer c.reader.Unlock()
	for {
		select {
		case <-c.done:
			return 0, nil, net.ErrClosed
		default:
		}
		c.deadline.Lock()
		dl, wake := c.deadline.read, c.deadline.wake
		c.deadline.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}
		select {
		case d := <-c.recv:
			stop(timer)
			if d.err != nil {
				datagramPool.Put(d.buf)
				return 0, d.from, d.err
			}
			n := copy(b, d.b)
			datagramPool.Put(d.buf)
			return n, d.from, nil
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-wake:
			stop(timer) // deadline changed
		case <-c.done:
			stop(timer)
			return 0, nil, net.ErrClosed
		}
	}
}

func stop(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

func (c *egressPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	dst, err := addrIP(addr)
	if err != nil {
		return 0, err
	}
	s, err := c.socketFor(dst)
	if err != nil {
		return 0, err
	}
	c.deadline.Lock()
	wd := c.deadline.write
	c.deadline.Unlock()
	if !wd.IsZero() {
		_ = s.conn.SetWriteDeadline(wd)
	}
	return s.conn.WriteTo(b, addr)
}

func addrIP(addr net.Addr) (netip.Addr, error) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return netip.Addr{}, &net.AddrError{Err: "invalid address", Addr: a.String()}
		}
		return ip.Unmap(), nil
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.Addr{}, err
	}
	return ap.Addr().Unmap(), nil
}

func (c *egressPacketConn) Close() error {
	var result error
	c.once.Do(func() {
		close(c.done)
		c.mu.Lock()
		c.closed = true
		for _, s := range c.sockets {
			result = errors.Join(result, s.conn.Close())
		}
		c.sockets = nil
		c.mu.Unlock()
		c.wg.Wait()
	})
	return result
}

func (c *egressPacketConn) LocalAddr() net.Addr { return c.primary.conn.LocalAddr() }

func (c *egressPacketConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *egressPacketConn) SetReadDeadline(t time.Time) error {
	c.deadline.Lock()
	c.deadline.read = t
	close(c.deadline.wake)
	c.deadline.wake = make(chan struct{})
	c.deadline.Unlock()
	return nil
}

func (c *egressPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadline.Lock()
	c.deadline.write = t
	c.deadline.Unlock()
	return nil
}

func (c *egressPacketConn) each(f func(net.PacketConn) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result error
	for _, s := range c.sockets {
		result = errors.Join(result, f(s.conn))
	}
	return result
}

func (c *egressPacketConn) SetReadBuffer(n int) error {
	return c.each(func(p net.PacketConn) error {
		if b, ok := p.(interface{ SetReadBuffer(int) error }); ok {
			return b.SetReadBuffer(n)
		}
		return nil
	})
}

func (c *egressPacketConn) SetWriteBuffer(n int) error {
	return c.each(func(p net.PacketConn) error {
		if b, ok := p.(interface{ SetWriteBuffer(int) error }); ok {
			return b.SetWriteBuffer(n)
		}
		return nil
	})
}

// NetworkPath is the primary socket's path; secondary sockets are recreated
// on invalidation instead of ending the flow.
func (c *egressPacketConn) NetworkPath() netstate.Path {
	if p, ok := c.primary.conn.(interface{ NetworkPath() netstate.Path }); ok {
		return p.NetworkPath()
	}
	return netstate.Path{}
}

func (c *egressPacketConn) NetworkInvalidated() bool { return invalidated(c.primary.conn) }

func (c *egressPacketConn) SetNetworkRecovery(handler func()) {
	c.mu.Lock()
	c.recovery = handler
	c.mu.Unlock()
	_ = c.each(func(p net.PacketConn) error {
		if r, ok := p.(interface{ SetNetworkRecovery(func()) }); ok {
			r.SetNetworkRecovery(handler)
		}
		return nil
	})
}

// Interfaces lists the egress interfaces with an open socket, for tests and
// diagnostics.
func (c *egressPacketConn) Interfaces() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.sockets))
	for name := range c.sockets {
		out = append(out, name)
	}
	return out
}
