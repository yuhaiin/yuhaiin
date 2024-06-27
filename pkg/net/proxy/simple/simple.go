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
)

type Simple struct {
	netapi.EmptyDispatch

	p netapi.Proxy

	addrs      []netapi.Address
	index      atomic.Uint32
	updateTime time.Time
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
			addrs: addrs,
			p:     p,
		}

		return simple, nil
	}
}

func (c *Simple) dial(ctx context.Context, addr netapi.Address, length int) (net.Conn, error) {
	ctx, cancel, er := dialer.PartialDeadlineCtx(ctx, length)
	if er != nil {
		// Ran out of time.
		return nil, er
	}
	defer cancel()

	if c.p != nil && !point.IsBootstrap(c.p) {
		return c.p.Conn(ctx, addr)
	}

	return netapi.DialHappyEyeballs(ctx, addr)
}

func (c *Simple) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	return c.dialGroup(ctx)
	// tconn, ok := conn.(*net.TCPConn)
	// if ok {
	// _ = tconn.SetKeepAlive(true)
	// https://github.com/golang/go/issues/48622
	// _ = tconn.SetKeepAlivePeriod(time.Minute * 3)
	// }
}

func (c *Simple) dialGroup(ctx context.Context) (net.Conn, error) {
	ctx = netapi.WithContext(ctx)

	var err error
	var conn net.Conn

	lastIndex := c.index.Load()
	index := lastIndex
	if lastIndex != 0 && time.Since(c.updateTime) > time.Minute*15 {
		index = 0
	}

	length := len(c.addrs)

	conn, err = c.dial(ctx, c.addrs[index], length)
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

		con, er := c.dial(ctx, addr, length)
		if er != nil {
			err = errors.Join(err, er)
			continue
		}

		conn = con
		c.index.Store(uint32(i))

		if i != 0 {
			c.updateTime = time.Now()
		}
		break
	}

	if conn == nil {
		return nil, fmt.Errorf("simple dial failed: %w", err)
	}

	return conn, nil
}

type PacketDirectKey struct{}

func (c *Simple) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	if ctx.Value(PacketDirectKey{}) == true {
		return direct.Default.PacketConn(ctx, addr)
	}

	if c.p != nil && !point.IsBootstrap(c.p) {
		return c.p.PacketConn(ctx, addr)
	}

	conn, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}

	if uc, ok := conn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(64 * 1024)
		_ = uc.SetWriteBuffer(64 * 1024)
	}

	ctx = netapi.WithContext(ctx)

	ur, err := netapi.ResolveUDPAddr(ctx, c.addrs[c.index.Load()])
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
