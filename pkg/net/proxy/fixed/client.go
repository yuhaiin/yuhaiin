package fixed

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"google.golang.org/protobuf/proto"
)

var refreshTimeout = int64(10 * time.Minute)

type Addr struct {
	a         netapi.Address
	Interface string
}

type Client struct {
	p            netapi.Proxy
	addrs        []Addr
	errCount     durationCounter
	refreshTime  atomic.Int64
	index        atomic.Uint32
	nonBootstrap bool
}

func init() {
	register.RegisterPoint(NewClient)
	register.RegisterPoint(NewClientv2)
	register.RegisterPoint(func(c *node.Simple, p netapi.Proxy) (netapi.Proxy, error) {
		return NewClient(node.Fixed_builder{
			Host:             proto.String(c.GetHost()),
			Port:             proto.Int32(c.GetPort()),
			AlternateHost:    c.GetAlternateHost(),
			NetworkInterface: proto.String(c.GetNetworkInterface()),
		}.Build(), p)
	})
}

func NewClient(c *node.Fixed, p netapi.Proxy) (netapi.Proxy, error) {
	var addrs []*node.Fixedv2Address
	addrs = append(addrs, node.Fixedv2Address_builder{
		Host:             proto.String(net.JoinHostPort(c.GetHost(), fmt.Sprint(c.GetPort()))),
		NetworkInterface: proto.String(c.GetNetworkInterface()),
	}.Build())
	for _, v := range c.GetAlternateHost() {
		addrs = append(addrs, node.Fixedv2Address_builder{
			Host:             proto.String(net.JoinHostPort(v.GetHost(), fmt.Sprint(v.GetPort()))),
			NetworkInterface: proto.String(c.GetNetworkInterface()),
		}.Build())
	}

	return NewClientv2(node.Fixedv2_builder{Addresses: addrs}.Build(), p)
}

func NewClientv2(c *node.Fixedv2, p netapi.Proxy) (netapi.Proxy, error) {
	var addrs []Addr

	var er error
	for _, v := range c.GetAddresses() {
		addr, err := netapi.ParseAddress("", v.GetHost())
		if err == nil {
			addrs = append(addrs, Addr{
				a:         addr,
				Interface: v.GetNetworkInterface(),
			})
		} else {
			er = errors.Join(er, err)
		}
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no valid addresses: %w", er)
	}

	simple := &Client{
		addrs:        addrs,
		p:            p,
		nonBootstrap: p != nil && !register.IsZero(p),
	}

	return simple, nil
}

func (c *Client) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	return c.dialHappyEyeballsv2(ctx)
}

func (c *Client) dialSingle(ctx context.Context, addr Addr) (net.Conn, error) {
	if c.nonBootstrap {
		return c.p.Conn(ctx, addr.a)
	} else {
		if addr.Interface != "" {
			netapi.GetContext(ctx).ConnOptions().SetBindInterface(addr.Interface)
		}
		return dialer.DialHappyEyeballsv2(ctx, addr.a)
	}
}

func (c *Client) dialHappyEyeballsv2(ctx context.Context) (net.Conn, error) {
	if len(c.addrs) == 1 {
		return c.dialSingle(ctx, c.addrs[0])
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	lastIndex := c.lastIndex()

	type res struct {
		c     net.Conn
		err   error
		index int
	}
	resc := make(chan res)           // must be unbuffered
	failBoost := make(chan struct{}) // best effort send on dial failure

	dial := func(index int) {
		conn, err := c.dialSingle(ctx, c.addrs[index])
		if err != nil {
			// Best effort wake-up a pending dial.
			// e.g. IPv4 dials failing quickly on an IPv6-only system.
			// In that case we don't want to wait 300ms per IPv4 before
			// we get to the IPv6 addresses.
			select {
			case failBoost <- struct{}{}:
			default:
			}

			if index == 0 {
				c.errCount.Inc()
			}
		}

		select {
		case resc <- res{conn, err, index}:
		case <-ctx.Done():
			if err == nil {
				if er := conn.Close(); er != nil {
					log.Warn("failed to close connection", "err", er)
				}
			}
		}
	}

	go func() {
		go dial(lastIndex)
		for i := range c.addrs {
			if i == lastIndex {
				continue
			}

			timer := time.NewTimer(time.Millisecond * 650)
			select {
			case <-timer.C:
			case <-failBoost:
				timer.Stop()
			case <-ctx.Done():
				timer.Stop()
				return
			}

			go dial(i)
		}
	}()

	var firstErr error
	var fails int
	for {
		select {
		case r := <-resc:
			if r.err == nil {
				c.successIndex(lastIndex, r.index)
				return r.c, nil
			}

			fails++
			if firstErr == nil {
				firstErr = r.err
			}
			if fails == len(c.addrs) {
				return nil, firstErr
			}

		case <-ctx.Done():
			return nil, fmt.Errorf("simple dial timeout: %w", errors.Join(firstErr, ctx.Err()))
		}
	}
}

func (c *Client) lastIndex() int {
	lastIndex := c.index.Load()
	if lastIndex != 0 && system.CheapNowNano()-c.refreshTime.Load() > refreshTimeout {
		lastIndex = 0
	}

	return int(lastIndex)
}

func (c *Client) successIndex(lastIndex, index int) {
	if lastIndex == index {
		return
	}

	if index != 0 && c.errCount.Get() <= 5 {
		return
	}

	c.index.Store(uint32(index))

	if index == 0 {
		c.errCount.Reset()
	}

	if lastIndex == 0 {
		c.refreshTime.Store(system.CheapNowNano())
	}
}

/*
	func (c *Client) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
		index := c.index.Load()
		addr := c.addrs[index]

		if c.nonBootstrap {
			conn, err := c.p.PacketConn(ctx, addr.a)
			if err != nil {
				return nil, err
			}

			return &packetConnSingle{
				PacketConn: conn,
				addr:       addr.a,
			}, nil
		}

		ctx = netapi.WithContext(ctx)

		var uaddr *net.UDPAddr
		if !addr.a.IsFqdn() {
			uaddr = net.UDPAddrFromAddrPort(addr.a.(netapi.IPAddress).AddrPort())
		} else {
			ips, err := netapi.ResolverIP(ctx, addr.a.Hostname())
			if err != nil {
				return nil, err
			}

			uaddr = ips.RandUDPAddr(addr.a.Port())
		}

		conn, err := dialer.ListenPacket(ctx, "udp", "", func(o *dialer.Options) {
			if addr.Interface != "" {
				o.InterfaceName = addr.Interface
			}

			if uaddr != nil {
				o.PacketConnHintAddress = uaddr
			}

		})
		if err != nil {
			return nil, err
		}

		return &packetConnSingle{
			PacketConn: conn,
			addr:       uaddr,
		}, nil
	}
*/
func (c *Client) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	index := c.index.Load()
	addr := c.addrs[index]

	if c.nonBootstrap {
		conn, err := c.p.PacketConn(ctx, addr.a)
		if err != nil {
			return nil, err
		}

		return &packetConnSingle{
			PacketConn: conn,
			addr:       addr.a,
		}, nil
	}

	ctx = netapi.WithContext(ctx)

	addrs := make([]netip.AddrPort, 0, len(c.addrs))

	for _, v := range c.addrs {
		if !v.a.IsFqdn() {
			addrs = append(addrs, v.a.(netapi.IPAddress).AddrPort())
		} else {
			ips, err := netapi.ResolverIP(ctx, v.a.Hostname())
			if err != nil {
				return nil, err
			}

			addrs = append(addrs, netip.AddrPortFrom(ips.RandNetipAddr(), v.a.Port()))
		}
	}

	if index != 0 {
		addrs[0], addrs[index] = addrs[index], addrs[0]
	}

	conn, err := dialer.ListenPacket(ctx, "udp", "", func(o *dialer.Options) {
		if addr.Interface != "" {
			o.InterfaceName = addr.Interface
		}

		if len(addrs) > 0 {
			o.PacketConnHintAddress = net.UDPAddrFromAddrPort(addrs[0])
		}

	})
	if err != nil {
		return nil, err
	}

	return newPacketConn(conn, addrs), nil
}

func (c *Client) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	if c.nonBootstrap {
		return c.p.Ping(ctx, addr)
	}

	return direct.Default.Ping(ctx, addr)
}

func (c *Client) Dispatch(ctx context.Context, addr netapi.Address) (netapi.Address, error) {
	if c.nonBootstrap {
		return c.p.Dispatch(ctx, addr)
	}

	return direct.Default.Dispatch(ctx, addr)
}

func (c *Client) Close() error {
	if c.p != nil {
		return c.p.Close()
	}

	return nil
}

type packetConnSingle struct {
	net.PacketConn
	addr net.Addr
}

func (p *packetConnSingle) WriteTo(b []byte, addr net.Addr) (int, error) {
	return p.PacketConn.WriteTo(b, p.addr)
}

func (p *packetConnSingle) ReadFrom(b []byte) (int, net.Addr, error) {
	z, _, err := p.PacketConn.ReadFrom(b)
	return z, p.addr, err
}

// pcState represents the connection state.
type pcState struct {
	ua      *net.UDPAddr                // The locked remote peer address once probing is complete.
	addrs   []*net.UDPAddr              // Candidate addresses for fan-out during probing (pre-allocated).
	addrMap map[netip.AddrPort]struct{} // Map for O(1) lookup during ReadFrom.
	start   time.Time                   // When the probing phase started.
}

type packetConn struct {
	net.PacketConn
	state atomic.Pointer[pcState]
	wc    atomic.Int64 // Write counter to track the number of probing attempts.
}

// newPacketConn creates a packetConn in probing mode.
func newPacketConn(pc net.PacketConn, candidateAddrs []netip.AddrPort) *packetConn {
	st := &pcState{
		addrs:   make([]*net.UDPAddr, 0, len(candidateAddrs)),
		addrMap: make(map[netip.AddrPort]struct{}, len(candidateAddrs)),
		start:   time.Now(),
	}

	for _, ap := range candidateAddrs {
		// Normalize addresses (e.g., handle IPv4-mapped IPv6) to ensure consistent comparison.
		normalized := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())

		st.addrs = append(st.addrs, net.UDPAddrFromAddrPort(normalized))
		st.addrMap[normalized] = struct{}{}
	}

	p := &packetConn{PacketConn: pc}
	p.state.Store(st)
	return p
}

// WriteTo sends packets.
// In probing mode, it fans out packets to all candidate addresses.
// Once a peer is locked (or timeout occurs), it sends only to the selected peer.
func (p *packetConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	st := p.state.Load()
	if st == nil {
		return 0, errors.New("connection closed")
	}

	// 1. Locked mode: Send directly to the selected peer.
	if st.ua != nil {
		return p.PacketConn.WriteTo(b, st.ua)
	}

	// 2. Check for fallback/timeout to force a lock.
	cc := p.wc.Add(1)
	if cc > 5 || time.Since(st.start) > 3*time.Second {
		if len(st.addrs) > 0 {
			// Lock to the first candidate address as a fallback.
			return p.PacketConn.WriteTo(b, st.addrs[0])
		}
		return 0, errors.New("no available candidate addresses")
	}

	// 3. Probing mode: Fan-out writes to all candidate addresses.
	var lastErr error
	sentCount := 0
	for _, ua := range st.addrs {
		if _, err := p.PacketConn.WriteTo(b, ua); err != nil {
			lastErr = err
			continue
		}
		sentCount++
	}

	if sentCount == 0 {
		return 0, fmt.Errorf("failed to write to any address: %w", lastErr)
	}

	// Logical write: return the length of the payload once.
	return len(b), nil
}

// ReadFrom receives packets.
// During probing, it filters for packets from candidate addresses and locks on the first responder.
// After locking, it silently drops packets from other addresses.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := p.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}

		ra, ok := addr.(*net.UDPAddr)
		if !ok {
			continue // Only handle UDP addresses.
		}

		st := p.state.Load()
		if st == nil {
			return 0, nil, errors.New("connection closed")
		}

		// 1. Locked mode: Accept packets only from the selected peer.
		if st.ua != nil {
			if sameUDPAddr(ra, st.ua) {
				return n, addr, nil
			}
			continue // Drop packets from non-locked addresses.
		}

		// 2. Probing mode: Check if the sender is in the candidate list.
		ap := ra.AddrPort()
		normalized := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())

		if _, exists := st.addrMap[normalized]; exists {
			p.lockPeer(ra) // Lock the first valid responder as the peer.
			return n, addr, nil
		}

		// 3. Timeout fallback for the receiver.
		if time.Since(st.start) > 3*time.Second && len(st.addrs) > 0 {
			p.lockPeer(st.addrs[0])
			continue
		}

		// If the packet doesn't match any candidate and we aren't timed out,
		// ignore it and wait for the next packet.
	}
}

// lockPeer atomically transitions the state from probing to locked mode.
func (p *packetConn) lockPeer(ua *net.UDPAddr) {
	for {
		old := p.state.Load()
		if old == nil || old.ua != nil {
			return // Already locked or closed.
		}

		// Create a new state representing the locked connection.
		// Note: addrMap and addrs are cleared to free memory.
		next := &pcState{
			ua:    ua,
			start: old.start,
		}

		if p.state.CompareAndSwap(old, next) {
			return
		}
	}
}

// sameUDPAddr compares two UDP addresses by IP and Port.
func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a.Port != b.Port {
		return false
	}
	return a.IP.Equal(b.IP)
}

type durationCounter struct {
	mu       sync.RWMutex
	count    int
	lastTime int64
}

func (c *durationCounter) Inc() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := system.CheapNowNano()

	if now-c.lastTime > int64(time.Second*5) {
		c.count++
		c.lastTime = now
	}
}

func (c *durationCounter) Get() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.count
}

func (c *durationCounter) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.count = 0
	c.lastTime = 0
}
