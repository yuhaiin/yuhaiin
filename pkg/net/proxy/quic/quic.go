package quic

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/quic-go/quic-go"
)

type Client struct {
	host *net.UDPAddr
	addr proxy.Address

	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	dialer      proxy.Proxy
	session     quic.Connection
	sessionLock sync.Mutex
}

func New(config *protocol.Protocol_Quic) protocol.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {
		uaddr, err := net.ResolveUDPAddr("udp", config.Quic.Host)
		if err != nil {
			return nil, err
		}

		c := &Client{
			host:       uaddr,
			dialer:     dialer,
			tlsConfig:  protocol.ParseTLSConfig(config.Quic.Tls),
			quicConfig: &quic.Config{
				// KeepAlivePeriod:      time.Second * 30,
				// ConnectionIDLength:   12,
				// HandshakeIdleTimeout: time.Second * 8,
				// MaxIdleTimeout:       time.Second * 30,
			},
		}

		if c.tlsConfig == nil {
			c.tlsConfig = &tls.Config{}
		}

		addr, err := proxy.ParseAddress(statistic.Type_udp, config.Quic.Host)
		if err != nil {
			return nil, err
		}

		c.addr = addr

		return c, nil
	}
}

func (c *Client) initSession() error {
	c.sessionLock.Lock()
	defer c.sessionLock.Unlock()

	if c.session != nil {
		return nil
	}
	conn, err := c.dialer.PacketConn(c.addr)
	if err != nil {
		return err
	}
	session, err := quic.DialEarly(conn, c.host, c.host.String(), c.tlsConfig, &quic.Config{})
	if err != nil {
		return err
	}
	go func() {
		select {
		case <-session.Context().Done():
			c.sessionLock.Lock()
			defer c.sessionLock.Unlock()
			session.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
			conn.Close()
			log.Println("session closed")
			c.session = nil
		}
	}()
	c.session = session
	return nil
}

func (c *Client) Conn(s proxy.Address) (net.Conn, error) {
	if err := c.initSession(); err != nil {
		return nil, err
	}
	// conn, err := c.dialer.PacketConn(s)
	// if err != nil {
	// 	return nil, err
	// }

	// session, err := quic.DialContext(
	// 	s.Context(),
	// 	conn,
	// 	c.host,
	// 	c.host.String(),
	// 	c.tlsConfig,
	// 	c.quicConfig,
	// )
	// if err != nil {
	// 	conn.Close()
	// 	return nil, err
	// }

	stream, err := c.session.OpenStream()
	if err != nil {
		// conn.Close()
		return nil, err
	}

	return &interConn{
		// raw: conn,
		// session: session,
		Stream: stream,
		local:  c.session.LocalAddr(),
		remote: c.session.RemoteAddr(),
	}, nil
}

func (c *Client) PacketConn(host proxy.Address) (net.PacketConn, error) {
	return c.dialer.PacketConn(host)
}

var _ net.Conn = (*interConn)(nil)

type interConn struct {
	// raw     net.PacketConn
	// session quic.Connection
	quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *interConn) Close() error {
	var err error
	if er := c.Stream.Close(); er != nil {
		errors.Join(err, er)
	}

	// if er := c.session.CloseWithError(quic.ApplicationErrorCode(quic.NoError), ""); er != nil {
	// errors.Join(err, er)
	// }

	// if er := c.raw.Close(); er != nil {
	// errors.Join(err, er)
	// }

	return err
}

func (c *interConn) LocalAddr() net.Addr { return c.local }

func (c *interConn) RemoteAddr() net.Addr { return c.remote }
