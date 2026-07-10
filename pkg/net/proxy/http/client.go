package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

type client struct {
	netapi.Proxy
	user, password string
}

type Config struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func init() {
	register.RegisterContractPoint("http", func(config contractnode.HTTP, p netapi.Proxy) (netapi.Proxy, error) {
		return NewClient(Config{
			User:     config.User,
			Password: config.Password,
		}, p)
	})
}

func NewClient(config Config, p netapi.Proxy) (netapi.Proxy, error) {
	return &client{
		Proxy:    p,
		user:     config.User,
		password: config.Password,
	}, nil
}

func (c *client) Conn(ctx context.Context, s netapi.Address) (net.Conn, error) {
	conn, err := c.Proxy.Conn(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("dialer conn failed: %w", err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{},
		Header: make(http.Header),
		Host:   s.String(),
	}

	if c.user != "" || c.password != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.user+":"+c.password)))
	}

	err = req.Write(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("write request failed: %w", err)
	}

	cconn := pool.NewBufioConnSize(conn, configuration.UDPBufferSize.Load())

	var resp *http.Response
	err = cconn.BufioRead(func(r *bufio.Reader) error {
		resp, err = http.ReadResponse(r, req)
		if err != nil {
			return fmt.Errorf("read response failed: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status code not ok: %d", resp.StatusCode)
		}

		return nil
	})
	if err != nil {
		cconn.Close()
		return nil, err
	}

	return &clientConn{Conn: cconn, resp: resp}, nil
}

type clientConn struct {
	net.Conn
	resp *http.Response
}

func (c *clientConn) Close() error {
	c.resp.Body.Close()
	return c.Conn.Close()
}
