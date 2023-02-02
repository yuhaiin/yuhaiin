package quic

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/quic-go/quic-go"
)

type Client struct {
	addr       *net.UDPAddr
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	dialer     proxy.Proxy
}

func New(config *protocol.Protocol_Quic) protocol.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {
		c := &Client{
			dialer:    dialer,
			tlsConfig: protocol.ParseTLSConfig(config.Quic.Tls),
			quicConfig: &quic.Config{
				KeepAlivePeriod:      time.Second * 30,
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

func (c *Client) Conn(s proxy.Address) (net.Conn, error) {
	conn, err := c.dialer.PacketConn(s)
	if err != nil {
		return nil, err
	}
	session, err := quic.DialContext(s.Context(), conn, c.addr, "", c.tlsConfig, c.quicConfig)
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

func (c *Client) PacketConn(host proxy.Address) (net.PacketConn, error) {
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
