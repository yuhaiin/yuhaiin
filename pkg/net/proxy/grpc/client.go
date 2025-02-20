package grpc

import (
	context "context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	ytls "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
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
		tlsConfig: ytls.ParseTLSConfig(config.GetTls()),
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

	clientConn, err := grpc.NewClient("passthrough://yuhaiin-server",
		// grpc.WithConnectParams(grpc.ConnectParams{
		// Backoff: backoff.Config{
		// 	BaseDelay:  500 * time.Millisecond,
		// 	Multiplier: 1.5,
		// 	Jitter:     0.2,
		// 	MaxDelay:   19 * time.Second,
		// },
		// MinConnectTimeout: 5 * time.Second,
		// }),
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

func (c *client) Conn(_ context.Context, addr netapi.Address) (net.Conn, error) {
	stream, err := c.connect()
	if err != nil {
		return nil, err
	}

	client := NewStreamClient(stream)
	conn, err := client.Conn(context.TODO())
	if err != nil {
		return nil, err
	}

	c1, c2 := pipe.Pipe()

	go func() {
		defer c1.CloseWrite()
		for {
			data, err := conn.Recv()
			if err != nil {
				if err != io.EOF {
					log.Error("grpc client conn recv failed", "err", err)
				}
				return
			}

			_, err = c1.Write(data.Value)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer c1.Close()
		defer conn.CloseSend()
		for {
			buf := make([]byte, pool.DefaultSize)
			n, err := c1.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Error("grpc client conn read failed", "err", err)
				}
				return
			}

			err = conn.Send(&wrapperspb.BytesValue{Value: buf[:n]})
			if err != nil {
				return
			}
		}
	}()

	c2.SetLocalAddr(caddr{})
	c2.SetRemoteAddr(addr)

	return c2, nil
}

type caddr struct{}

func (caddr) Network() string { return "tcp" }
func (caddr) String() string  { return "GRPC" }
