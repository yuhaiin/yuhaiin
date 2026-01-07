package proxy

import (
	"bufio"
	"context"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	proxyproto "github.com/pires/go-proxyproto"
)

func init() {
	register.RegisterPoint(NewClient)
	register.RegisterTransport(NewServer)
}

type Client struct {
	netapi.Proxy
}

func NewClient(_ *node.Proxy, proxy netapi.Proxy) (netapi.Proxy, error) {
	return &Client{Proxy: proxy}, nil
}

func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	conn, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	// Create a proxyprotocol header or use HeaderProxyFromAddrs() if you
	// have two conn's
	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: int(rand.UintN(65535)),
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.IPv4(10, 97, 70, 134),
			Port: 3000,
		},
	}

	// After the connection was created write the proxy headers first
	_, err = header.WriteTo(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

type Server struct {
	netapi.Listener
}

func NewServer(_ *config.Proxy, ii netapi.Listener) (netapi.Listener, error) {
	return &Server{Listener: ii}, nil
}

func (s *Server) Accept() (net.Conn, error) {
	conn, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return newConn(conn), nil
}

type conn struct {
	net.Conn
	br *bufio.Reader

	handshake atomic.Bool
	mu        sync.Mutex
}

func newConn(c net.Conn) net.Conn {
	return &conn{Conn: c}
}

func (c *conn) Handshake() error {
	if c.handshake.Load() {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.handshake.Load() {
		return nil
	}

	c.handshake.Store(true)

	br := bufio.NewReader(c.Conn)

	_, err := proxyproto.ReadTimeout(br, time.Second*15)
	if err != nil {
		return err
	}
	c.br = br
	return nil
}

func (c *conn) Read(b []byte) (int, error) {
	if !c.handshake.Load() {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.br != nil {
		return c.br.Read(b)
	}

	return c.Conn.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	if !c.handshake.Load() {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}

	return c.Conn.Write(b)
}
