package simple

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

type Simple struct {
	packetDirect bool
	tlsConfig    *tls.Config
	addr         proxy.Address
}

func New(c *protocol.Protocol_Simple) protocol.WrapProxy {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		tls := protocol.ParseTLSConfig(c.Simple.Tls)
		if tls != nil && !tls.InsecureSkipVerify && tls.ServerName == "" {
			tls.ServerName = c.Simple.GetHost()
		}

		return &Simple{
			addr:         proxy.ParseAddressSplit("", c.Simple.GetHost(), proxy.ParsePort(c.Simple.GetPort())),
			packetDirect: c.Simple.PacketConnDirect,
			tlsConfig:    tls,
		}, nil
	}
}

func (c *Simple) Conn(proxy.Address) (net.Conn, error) {
	host, err := c.addr.IPHost()
	if err != nil {
		return nil, fmt.Errorf("get host failed: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("simple dial failed: %w", err)
	}

	if c.tlsConfig != nil {
		conn = tls.Client(conn, c.tlsConfig)
	}

	return conn, nil
}

func (c *Simple) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	if c.packetDirect {
		return direct.Default.PacketConn(addr)
	}

	conn, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}

	uaddr, err := c.addr.UDPAddr()
	if err != nil {
		return nil, err
	}

	return &packetConn{PacketConn: conn, addr: uaddr}, nil
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
