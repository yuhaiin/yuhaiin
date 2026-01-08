package fixed

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
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
	udpDetect    bool
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
		udpDetect:    c.GetUdpHappyEyeballs(),
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

func (c *Client) resolverUDPAddr(ctx context.Context, addr netapi.Address) (*net.UDPAddr, error) {
	if addr.IsFqdn() {
		ips, err := netapi.ResolverIP(ctx, addr.Hostname())
		if err != nil {
			return nil, err
		}

		return ips.RandUDPAddr(addr.Port()), nil
	}

	return net.UDPAddrFromAddrPort(addr.(netapi.IPAddress).AddrPort()), nil
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

	uaddr, err := c.resolverUDPAddr(ctx, addr.a)
	if err != nil {
		return nil, err
	}

	conn, err := dialer.ListenPacket(ctx, "udp", "", func(o *dialer.Options) {
		if addr.Interface != "" {
			o.InterfaceName = addr.Interface
		}

		o.PacketConnHintAddress = uaddr
	})
	if err != nil {
		return nil, err
	}

	if !c.udpDetect || len(c.addrs) <= 1 {
		return &packetConnSingle{
			PacketConn: conn,
			addr:       uaddr,
		}, nil
	}

	addrs := []*net.UDPAddr{uaddr}

	for i, v := range c.addrs {
		if i == int(index) {
			continue
		}

		uaddr, err := c.resolverUDPAddr(ctx, v.a)
		if err != nil {
			continue
		}

		addrs = append(addrs, uaddr)
	}

	readAddr := make(chan *net.UDPAddr)
	found := atomic.Bool{}
	go func() {
		data := pool.GetBytes(configuration.UDPBufferSize.Load())
		defer pool.PutBytes(data)

		for {
			n, addr, err := conn.ReadFrom(data)
			if err != nil {
				log.Warn("udp read failed", "err", err)
				return
			}

			if n == 32 && [32]byte(data[:32]) == detectPacket2 {
				readAddr <- addr.(*net.UDPAddr)
				found.Store(true)
				break
			}
		}
	}()

	go func() {
		for i := range 4 {
			if i != 0 {
				time.Sleep(time.Millisecond * 200)
			}
			for _, uaddr := range addrs {
				if found.Load() {
					break
				}

				if _, err := conn.WriteTo(detectPacket1[:], uaddr); err != nil {
					log.Warn("udp write failed", "err", err, "addr", uaddr)
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		_ = conn.Close()
		return nil, ctx.Err()

	case addr := <-readAddr:
		return &packetConnSingle{
			PacketConn: conn,
			addr:       addr,
		}, nil
	}
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
_retry:
	z, _, err := p.PacketConn.ReadFrom(b)
	if err == nil && z == 32 && [32]byte(b[:32]) == detectPacket2 {
		goto _retry
	}
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
