package fixed

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"google.golang.org/protobuf/proto"
)

var refreshTimeout = int64(10 * time.Minute)

type Client struct {
	p            netapi.Proxy
	iface        string
	addrs        []netapi.Address
	errCount     durationCounter
	refreshTime  atomic.Int64
	index        atomic.Uint32
	nonBootstrap bool
}

func init() {
	register.RegisterPoint(NewClient)
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
	var addrs []netapi.Address

	var er error
	addr, err := netapi.ParseAddressPort("", c.GetHost(), uint16(c.GetPort()))
	if err == nil {
		addrs = append(addrs, addr)
	} else {
		er = errors.Join(er, err)
	}

	for _, v := range c.GetAlternateHost() {
		addr, err = netapi.ParseAddressPort("", v.GetHost(), uint16(v.GetPort()))
		if err == nil {
			addrs = append(addrs, addr)
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
		iface:        c.GetNetworkInterface(),
	}

	return simple, nil
}

func (c *Client) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	return c.dialHappyEyeballsv2(ctx)
}

func (c *Client) dialSingle(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	if c.nonBootstrap {
		return c.p.Conn(ctx, addr)
	} else {
		if c.iface != "" {
			netapi.GetContext(ctx).ConnOptions().SetBindInterface(c.iface)
		}
		return dialer.DialHappyEyeballsv2(ctx, addr)
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
				conn.Close()
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
	addr := c.addrs[c.index.Load()]

	if c.nonBootstrap {
		conn, err := c.p.PacketConn(ctx, addr)
		if err != nil {
			return nil, err
		}

		return &packetConn{conn, addr}, nil
	}

	ctx = netapi.WithContext(ctx)

	var uaddr *net.UDPAddr

	if !addr.IsFqdn() {
		uaddr = net.UDPAddrFromAddrPort(addr.(netapi.IPAddress).AddrPort())
	} else {
		ips, err := netapi.ResolverIP(ctx, addr.Hostname())
		if err != nil {
			return nil, err
		}

		uaddr = ips.RandUDPAddr(addr.Port())
	}

	conn, err := dialer.ListenPacket(ctx, "udp", "", func(o *dialer.Options) {
		if c.iface != "" {
			o.InterfaceName = c.iface
		}

		o.PacketConnHintAddress = uaddr
	})
	if err != nil {
		return nil, err
	}

	return &packetConn{conn, uaddr}, nil
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

type packetConn struct {
	net.PacketConn
	addr net.Addr
}

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return p.PacketConn.WriteTo(b, p.addr)
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	z, _, err := p.PacketConn.ReadFrom(b)
	return z, p.addr, err
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
