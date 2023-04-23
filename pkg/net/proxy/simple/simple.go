package simple

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

type Simple struct {
	proxy.EmptyDispatch

	packetDirect bool
	tlsConfig    *tls.Config
	addrs        []proxy.Address
	serverNames  []string

	index      int
	updateTime time.Time
}

func New(c *protocol.Protocol_Simple) protocol.WrapProxy {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		var servernames []string
		tls := protocol.ParseTLSConfig(c.Simple.Tls)
		if tls != nil {
			if !tls.InsecureSkipVerify && tls.ServerName == "" {
				tls.ServerName = c.Simple.GetHost()
			}
			servernames = c.Simple.Tls.ServerNames
		}

		var addrs []proxy.Address
		addrs = append(addrs, proxy.ParseAddressPort(0, c.Simple.GetHost(), proxy.ParsePort(c.Simple.GetPort())))
		for _, v := range c.Simple.GetAlternateHost() {
			addrs = append(addrs, proxy.ParseAddressPort(0, v.GetHost(), proxy.ParsePort(v.GetPort())))
		}

		return &Simple{
			addrs:        addrs,
			packetDirect: c.Simple.PacketConnDirect,
			tlsConfig:    tls,
			serverNames:  servernames,
		}, nil
	}
}

func (c *Simple) dial(addr proxy.Address) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*4)
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

func (c *Simple) Conn(_ context.Context, d proxy.Address) (net.Conn, error) {
	var conn net.Conn
	var err error

	if c.index != 0 && !c.updateTime.IsZero() {
		if time.Since(c.updateTime) <= time.Minute*10 {
			conn, _ = c.dial(c.addrs[c.index])
		} else {
			c.updateTime = time.Time{}
		}
	}

	if conn == nil {
		for i, addr := range c.addrs {
			con, er := c.dial(addr)
			if er != nil {
				err = errors.Join(err, er)
				continue
			}

			conn = con
			c.index = i

			if i != 0 {
				c.updateTime = time.Now()
			}
			break
		}
	}

	if conn == nil {
		return nil, fmt.Errorf("simple dial failed: %w", err)
	}

	conn.(*net.TCPConn).SetKeepAlive(true)

	if c.tlsConfig != nil {
		tlsConfig := c.tlsConfig
		if sl := len(c.serverNames); sl > 1 {
			tlsConfig = tlsConfig.Clone()
			tlsConfig.ServerName = c.serverNames[rand.Intn(sl)]
		}
		conn = tls.Client(conn, tlsConfig)
	}

	return conn, nil
}

func (c *Simple) PacketConn(ctx context.Context, addr proxy.Address) (net.PacketConn, error) {
	if c.packetDirect {
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
