package simple

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
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

var refreshTimeout = int64(10 * time.Minute)

type Simple struct {
	p            netapi.Proxy
	addrs        []netapi.Address
	refreshTime  atomic.Int64
	index        atomic.Uint32
	errCount     durationCounter
	nonBootstrap bool
	netapi.EmptyDispatch
}

func init() {
	point.RegisterProtocol(NewClient)
}

func NewClient(c *protocol.Protocol_Simple) point.WrapProxy {
	return func(p netapi.Proxy) (netapi.Proxy, error) {
		var addrs []netapi.Address
		addrs = append(addrs, netapi.ParseAddressPort("", c.Simple.GetHost(), uint16(c.Simple.GetPort())))
		for _, v := range c.Simple.GetAlternateHost() {
			addrs = append(addrs, netapi.ParseAddressPort("", v.GetHost(), uint16(v.GetPort())))
		}

		simple := &Simple{
			addrs:        addrs,
			p:            p,
			nonBootstrap: p != nil && !point.IsBootstrap(p),
		}

		return simple, nil
	}
}

func (c *Simple) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	return c.dialHappyEyeballsv2(ctx)
}

func (c *Simple) dialSingle(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	if c.nonBootstrap {
		return c.p.Conn(ctx, addr)
	} else {
		return dialer.DialHappyEyeballsv2(ctx, addr)
	}
}

func (c *Simple) dialHappyEyeballsv2(ctx context.Context) (net.Conn, error) {
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

func (c *Simple) lastIndex() int {
	lastIndex := c.index.Load()
	if lastIndex != 0 && system.CheapNowNano()-c.refreshTime.Load() > refreshTimeout {
		lastIndex = 0
	}

	return int(lastIndex)
}

func (c *Simple) successIndex(lastIndex, index int) {
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

type PacketDirectKey struct{}

func (c *Simple) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	if ctx.Value(PacketDirectKey{}) == true {
		return direct.Default.PacketConn(ctx, addr)
	}

	if c.nonBootstrap {
		return c.p.PacketConn(ctx, addr)
	}

	ctx = netapi.WithContext(ctx)

	ur, err := dialer.ResolveUDPAddr(ctx, c.addrs[c.index.Load()])
	if err != nil {
		return nil, err
	}

	var localAddr string
	if dialer.DefaultIPv6PreferUnicastLocalAddr && dialer.DefaultInterfaceName != "" && dialer.DefaultInterfaceIndex != 0 {
		if ur.IP.IsGlobalUnicast() && !ur.IP.IsPrivate() && ur.IP.To4() == nil && ur.IP.To16() != nil {
			if addr := dialer.GetUnicastAddr(true, "udp", dialer.DefaultInterfaceName, dialer.DefaultInterfaceIndex); addr != nil {
				localAddr = addr.String()
			}
		}
	}

	conn, err := dialer.ListenPacket("udp", localAddr, dialer.WithTryUpgradeToBatch())
	if err != nil {
		return nil, err
	}

	if uc, ok := conn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(64 * 1024)
		_ = uc.SetWriteBuffer(64 * 1024)
	}

	return &packetConn{conn, ur}, nil
}

type packetConn struct {
	net.PacketConn
	addr *net.UDPAddr
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
