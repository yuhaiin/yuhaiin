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

	// if !addr.a.IsFqdn() {
	// 	uaddr = net.UDPAddrFromAddrPort(addr.a.(netapi.IPAddress).AddrPort())
	// } else {
	// 	ips, err := netapi.ResolverIP(ctx, addr.a.Hostname())
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	uaddr = ips.RandUDPAddr(addr.a.Port())
	// }

	conn, err := dialer.ListenPacket(ctx, "udp", "", func(o *dialer.Options) {
		if addr.Interface != "" {
			o.InterfaceName = addr.Interface
		}

		for _, v := range addrs {
			o.PacketConnHintAddress = net.UDPAddrFromAddrPort(v)
			break
		}
	})
	if err != nil {
		return nil, err
	}

	return &packetConn{
		PacketConn: conn,
		addrs:      addrs,
	}, nil
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

type packetConn struct {
	net.PacketConn
	mu     sync.RWMutex
	addrs  []netip.AddrPort
	uaddr  atomic.Pointer[net.UDPAddr]
	rc, wc atomic.Int64
}

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ua := p.uaddr.Load()
	if ua != nil {
		return p.PacketConn.WriteTo(b, ua)
	}

	cc := p.wc.Add(1)

	p.mu.RLock()
	addrs := p.addrs
	p.mu.RUnlock()
	if len(addrs) == 0 {
		return 0, errors.New("no available addresses to write to")
	}

	if cc > 10 {
		// After 10 packets, we should have received a response and locked an address.
		// If not, just use the first address as a fallback.
		ua = net.UDPAddrFromAddrPort(addrs[0])
		return p.PacketConn.WriteTo(b, ua)
	}

	// For the first 10 packets, send to all available addresses to find a working path.
	var lastErr error
	sent := false
	for _, v := range addrs {
		ua = net.UDPAddrFromAddrPort(v)
		if _, err := p.PacketConn.WriteTo(b, ua); err != nil {
			lastErr = err
		} else {
			sent = true
		}
	}

	if !sent {
		return 0, fmt.Errorf("failed to write to any address: %w", lastErr)
	}

	return len(b), nil
}

func (p *packetConn) storeUDPAddr(ua *net.UDPAddr) {
	p.uaddr.CompareAndSwap(nil, ua)
	p.mu.Lock()
	p.addrs = nil
	p.mu.Unlock()
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	z, addr, err := p.PacketConn.ReadFrom(b)
	if p.uaddr.Load() != nil {
		return z, p.uaddr.Load(), err
	}

	cc := p.rc.Add(1)

	p.mu.RLock()
	addrs := p.addrs
	p.mu.RUnlock()

	ua, ok := addr.(*net.UDPAddr)
	if ok {
		addrPort := ua.AddrPort()
		addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())

		for _, v := range addrs {
			if addrPort.Compare(v) == 0 {
				log.Info("--------set uaddr", "ua", ua)
				p.storeUDPAddr(ua)
				break
			}
		}
	}

	if p.uaddr.Load() == nil && cc > 10 && len(addrs) > 0 {
		ua = net.UDPAddrFromAddrPort(addrs[0])
		log.Info("--------set uaddr, over 10", "ua", ua)
		p.storeUDPAddr(ua)
	}

	return z, addr, err

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
