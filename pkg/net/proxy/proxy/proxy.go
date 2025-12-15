package proxy

import (
	"bufio"
	"context"
	"math/rand/v2"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
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
	netapi.PacketListener
	*netapi.HandshakeListener
}

func (s *Server) Close() error {
	return s.HandshakeListener.Close()
}

func NewServer(_ *config.Proxy, ii netapi.Listener) (netapi.Listener, error) {
	return &Server{
		PacketListener: ii,
		HandshakeListener: netapi.NewHandshakeListener(ii, func(_ context.Context, conn net.Conn) (net.Conn, error) {
			bufconn := pool.NewBufioConnSize(conn, configuration.SnifferBufferSize)

			err := bufconn.BufioRead(func(r *bufio.Reader) error {
				_, err := proxyproto.ReadTimeout(r, time.Second*15)
				return err
			})
			if err != nil {
				_ = bufconn.Close()
				return nil, err
			}

			return bufconn, nil
		}, log.Error),
	}, nil
}
