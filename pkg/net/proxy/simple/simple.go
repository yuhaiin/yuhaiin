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
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

type Simple struct {
	netapi.EmptyDispatch

	addrs      []netapi.Address
	refresh    atomic.Bool
	index      atomic.Uint32
	updateTime time.Time
	timeout    time.Duration
}

func init() {
	point.RegisterProtocol(NewClient)
}

func NewClient(c *protocol.Protocol_Simple) point.WrapProxy {
	return func(p netapi.Proxy) (netapi.Proxy, error) {
		var addrs []netapi.Address
		addrs = append(addrs, netapi.ParseAddressPort(0, c.Simple.GetHost(), netapi.ParsePort(c.Simple.GetPort())))
		for _, v := range c.Simple.GetAlternateHost() {
			addrs = append(addrs, netapi.ParseAddressPort(0, v.GetHost(), netapi.ParsePort(v.GetPort())))
		}

		timeout := time.Duration(0)

		if c.Simple.Timeout > 0 {
			timeout = time.Millisecond * time.Duration(c.Simple.Timeout)
		}

		simple := &Simple{
			addrs:   addrs,
			timeout: timeout,
		}

		return tls.NewClient(&protocol.Protocol_Tls{Tls: c.Simple.Tls})(simple)
	}
}

func (c *Simple) dial(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	var cancel context.CancelFunc
	if c.timeout > 0 {
		ctx, cancel = context.WithTimeout(context.TODO(), c.timeout)
	} else {
		ctx, cancel = context.WithTimeout(ctx, time.Second*3)
	}
	defer cancel()

	ip, err := addr.IP(ctx)
	if err != nil {
		return nil, err
	}

	con, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), addr.Port().String()))
	if err != nil {
		return nil, err
	}

	return con, nil
}

func (c *Simple) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	var conn net.Conn
	var err error

	index := c.index.Load()

	if index == 0 {
		conn, err = c.dialGroup(ctx)
	} else {
		conn, err = c.dial(ctx, c.addrs[index])

		if time.Since(c.updateTime) > time.Minute*15 && c.refresh.CompareAndSwap(false, true) {
			go func() {
				defer c.refresh.Store(false)
				con, err := c.dialGroup(ctx)
				if err != nil {
					return
				}
				con.Close()
			}()
		}
	}

	if err != nil {
		return nil, fmt.Errorf("simple dial failed: %w", err)
	}

	// tconn, ok := conn.(*net.TCPConn)
	// if ok {
	// _ = tconn.SetKeepAlive(true)
	// https://github.com/golang/go/issues/48622
	// _ = tconn.SetKeepAlivePeriod(time.Minute * 3)
	// }

	return conn, nil
}

func (c *Simple) dialGroup(ctx context.Context) (net.Conn, error) {
	var err error
	var conn net.Conn

	for i, addr := range c.addrs {
		con, er := c.dial(ctx, addr)
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
	if ctx.Value(PacketDirectKey{}) != true {
		return direct.Default.PacketConn(ctx, addr)
	}

	conn, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}

	uaddr, err := c.addrs[0].UDPAddr(ctx)
	if err != nil {
		return nil, err
	}

	return &packetConn{conn, uaddr}, nil
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
