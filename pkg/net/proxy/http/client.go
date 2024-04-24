package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

type client struct {
	netapi.Proxy
	user, password string
}

func init() {
	point.RegisterProtocol(NewClient)
}

func NewClient(config *protocol.Protocol_Http) point.WrapProxy {
	return func(p netapi.Proxy) (netapi.Proxy, error) {
		return &client{
			Proxy:    p,
			user:     config.Http.User,
			password: config.Http.Password,
		}, nil
	}
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

	bufioReader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(bufioReader, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read response failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("status code not ok: %d", resp.StatusCode)
	}

	conn, err = netapi.MergeBufioReaderConn(conn, bufioReader)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("merge bufio reader conn failed: %w", err)
	}

	return &clientConn{Conn: conn, resp: resp}, nil
}

type clientConn struct {
	net.Conn
	resp *http.Response
}

func (c *clientConn) Close() error {
	c.resp.Body.Close()
	return c.Conn.Close()
}
