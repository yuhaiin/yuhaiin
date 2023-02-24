package grpc

import (
	context "context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
)

type client struct {
	proxy.EmptyDispatch
	dialer proxy.Proxy

	clientConn *grpc.ClientConn
	client     StreamClient

	tlsConfig *tls.Config

	count     *atomic.Int64
	stopTimer *time.Timer
	mu        sync.Mutex
}

func New(config *protocol.Protocol_Grpc) protocol.WrapProxy {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		return &client{
			dialer:    p,
			count:     &atomic.Int64{},
			tlsConfig: protocol.ParseTLSConfig(config.Grpc.Tls),
		}, nil
	}
}

func (c *client) initClient() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.clientConn != nil {
		c.clientCountAdd()
		return nil
	}

	var tlsOption grpc.DialOption
	if c.tlsConfig == nil {
		tlsOption = grpc.WithInsecure()
	} else {
		tlsOption = grpc.WithTransportCredentials(credentials.NewTLS(c.tlsConfig))
	}

	clientConn, err := grpc.Dial("",
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithInitialWindowSize(65536),
		tlsOption,
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return c.dialer.Conn(proxy.EmptyAddr)
		}))
	if err != nil {
		return err
	}

	c.clientConn = clientConn
	c.client = NewStreamClient(clientConn)
	c.clientCountAdd()

	return nil
}

func (c *client) clientCountAdd() {
	if c.count.Add(1) == 1 && c.stopTimer != nil {
		c.stopTimer.Stop()
	}
}

func (c *client) clientCountSub() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.count.Add(-1) != 0 {
		return
	}

	if c.stopTimer == nil {
		c.stopTimer = time.AfterFunc(time.Minute, c.close)
	} else {
		c.stopTimer.Reset(time.Minute)
	}
}

func (c *client) reconnect() error {
	c.close()
	return c.initClient()
}

func (c *client) close() {
	c.mu.Lock()
	if c.clientConn != nil {
		c.clientConn.Close()
		c.clientConn = nil
		c.client = nil
	}
	c.mu.Unlock()
}

func (c *client) Conn(addr proxy.Address) (net.Conn, error) {
	if err := c.initClient(); err != nil {
		return nil, err
	}
	var retried bool

_retry:
	ctx, cancel := context.WithCancel(context.TODO())
	con, err := c.client.Conn(ctx)
	if err != nil {
		cancel()
		if !retried {
			if er := c.reconnect(); er != nil {
				return nil, er
			}
			retried = true
			goto _retry
		}
		return nil, err
	}

	return &conn{
		raw:   con,
		laddr: caddr{},
		close: func() {
			cancel()
			con.CloseSend()
			c.clientCountSub()
		},
		raddr: addr,
	}, nil
}

func (c *client) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	return c.dialer.PacketConn(addr)
}

type caddr struct{}

func (caddr) Network() string { return "tcp" }
func (caddr) String() string  { return "GRPC" }
