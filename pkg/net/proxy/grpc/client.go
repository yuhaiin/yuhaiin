package grpc

import (
	context "context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type client struct {
	netapi.Proxy

	clientConn *grpc.ClientConn

	tlsConfig *tls.Config

	mu sync.Mutex
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(config *protocol.Grpc, p netapi.Proxy) (netapi.Proxy, error) {
	return &client{
		Proxy:     p,
		tlsConfig: register.ParseTLSConfig(config.GetTls()),
	}, nil
}

func (c *client) connect() (*grpc.ClientConn, error) {
	conn := c.clientConn
	if conn != nil && conn.GetState() != connectivity.Shutdown {
		return conn, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	conn = c.clientConn
	if conn != nil && conn.GetState() != connectivity.Shutdown {
		return conn, nil
	}

	var tlsOption grpc.DialOption
	if c.tlsConfig == nil {
		tlsOption = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		tlsOption = grpc.WithTransportCredentials(credentials.NewTLS(c.tlsConfig))
	}

	clientConn, err := grpc.NewClient("yuhaiin-server",
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		tlsOption,
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return c.Proxy.Conn(ctx, netapi.EmptyAddr)
		}),
	)
	if err != nil {
		return nil, err
	}

	c.clientConn = clientConn

	return clientConn, nil
}

func (c *client) Close() error {
	var err error
	c.mu.Lock()
	if c.clientConn != nil {
		if er := c.clientConn.Close(); er != nil {
			err = errors.Join(err, er)
		}
		c.clientConn = nil
	}
	c.mu.Unlock()

	if er := c.Proxy.Close(); er != nil {
		err = errors.Join(err, er)
	}

	return err
}

func (c *client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	var retried bool

_retry:
	conn, err := c.connect()
	if err != nil {
		return nil, err
	}

	cc := NewStreamClient(conn)
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	con, err := cc.Conn(ctx)
	if err != nil {
		cancel()
		if !retried {
			c.Close()
			retried = true
			goto _retry
		}
		return nil, err
	}

	return newConn(con, caddr{}, addr, func() {
		cancel()
		_ = con.CloseSend()
	}), nil
}

type caddr struct{}

func (caddr) Network() string { return "tcp" }
func (caddr) String() string  { return "GRPC" }
