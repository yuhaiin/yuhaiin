package quic

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/lucas-clemente/quic-go"
)

type Client struct {
	addr       *net.UDPAddr
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	dialer     proxy.Proxy
}

func NewQUIC(config *node.PointProtocol_Quic) node.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {
		c := &Client{
			dialer:    dialer,
			tlsConfig: node.ParseTLSConfig(config.Quic.Tls),
			quicConfig: &quic.Config{
				KeepAlive:            true,
				ConnectionIDLength:   12,
				HandshakeIdleTimeout: time.Second * 8,
				MaxIdleTimeout:       time.Second * 30,
			},
		}

		if c.tlsConfig == nil {
			c.tlsConfig = &tls.Config{}
		}

		return c, nil
	}
}

func (c *Client) Conn(host string) (net.Conn, error) {
	conn, err := c.dialer.PacketConn(host)
	if err != nil {
		return nil, err
	}
	session, err := quic.DialContext(context.Background(), conn, c.addr, "", c.tlsConfig, c.quicConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}

	stream, err := session.OpenStream()
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &interConn{Stream: stream, local: session.LocalAddr(), remote: session.RemoteAddr()}, nil
}

func (c *Client) PacketConn(host string) (net.PacketConn, error) {
	return c.dialer.PacketConn(host)
}

var _ net.Conn = (*interConn)(nil)

type interConn struct {
	quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *interConn) LocalAddr() net.Addr {
	return c.local
}

func (c *interConn) RemoteAddr() net.Addr {
	return c.remote
}
