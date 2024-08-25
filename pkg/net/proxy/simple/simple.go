package simple

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type Simple struct {
	p            netapi.Proxy
	addrs        []netapi.Address
	updateTime   atomic.Int64
	index        atomic.Uint32
	errCount     atomic.Uint32
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
	// return c.dialGroup(ctx)
}

func (c *Simple) dialHappyEyeballsv1(ctx context.Context) (net.Conn, error) {
	ctx = netapi.WithContext(ctx)

	var err error
	var conn net.Conn

	lastIndex := c.index.Load()
	index := lastIndex
	if lastIndex != 0 && time.Duration(system.CheapNowNano()-c.updateTime.Load()) > time.Minute*15 {
		index = 0
	}

	length := len(c.addrs)

	dial := func(addr netapi.Address) (net.Conn, error) {
		ctx, cancel, er := dialer.PartialDeadlineCtx(ctx, length)
		if er != nil {
			// Ran out of time.
			return nil, er
		}
		defer cancel()

		return c.dialSingle(ctx, addr)
	}

	conn, err = dial(c.addrs[index])
	if err == nil {
		if lastIndex != 0 && index == 0 {
			c.index.Store(0)
		}

		return conn, nil
	}

	for i, addr := range c.addrs {
		if i == int(index) {
			continue
		}

		length--

		con, er := dial(addr)
		if er != nil {
			err = errors.Join(err, er)
			continue
		}

		conn = con
		c.index.Store(uint32(i))

		if i != 0 {
			c.updateTime.Store(system.CheapNowNano())
		}
		break
	}

	if conn == nil {
		return nil, fmt.Errorf("simple dial failed: %w", err)
	}

	return conn, nil
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

	lastIndex := c.index.Load()
	if lastIndex != 0 && time.Duration(system.CheapNowNano()-c.updateTime.Load()) > time.Minute*15 {
		lastIndex = 0
	}

	type res struct {
		c     net.Conn
		err   error
		index uint32
	}
	resc := make(chan res)           // must be unbuffered
	failBoost := make(chan struct{}) // best effort send on dial failure

	dial := func(index uint32, addr netapi.Address) {
		conn, err := c.dialSingle(ctx, addr)
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
				c.errCount.Add(1)
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
		go dial(lastIndex, c.addrs[lastIndex])
		for i, addr := range c.addrs {
			if i == int(lastIndex) {
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

			go dial(uint32(i), addr)
		}
	}()

	var firstErr error
	var fails int
	for {
		select {
		case r := <-resc:
			if r.err == nil {
				if lastIndex != r.index {
					if r.index == 0 || (r.index != 0 && c.errCount.Load() > 3) {
						c.index.Store(r.index)

						if r.index == 0 {
							c.errCount.Store(0)
						}

						if lastIndex == 0 {
							c.updateTime.Store(system.CheapNowNano())
						}
					}
				}

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

type PacketDirectKey struct{}

func (c *Simple) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	if ctx.Value(PacketDirectKey{}) == true {
		return direct.Default.PacketConn(ctx, addr)
	}

	if c.nonBootstrap {
		return c.p.PacketConn(ctx, addr)
	}

	conn, err := dialer.ListenPacket("udp", "", dialer.WithTryUpgradeToBatch())
	if err != nil {
		return nil, err
	}

	if uc, ok := conn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(64 * 1024)
		_ = uc.SetWriteBuffer(64 * 1024)
	}

	ctx = netapi.WithContext(ctx)

	ur, err := dialer.ResolveUDPAddr(ctx, c.addrs[c.index.Load()])
	if err != nil {
		return nil, err
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
