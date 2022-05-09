package client

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

type client struct {
	dialer         proxy.Proxy
	user, password string
}

func NewHttp(config *node.PointProtocol_Http) node.WrapProxy {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		return &client{p, config.Http.User, config.Http.Password}, nil
	}
}

func (c *client) Conn(host string) (net.Conn, error) {
	conn, err := c.dialer.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dialer conn failed: %w", err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: host},
		Header: make(http.Header),
		Host:   host,
	}

	if c.user != "" || c.password != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.user+":"+c.password)))
	}

	err = req.Write(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("write request failed: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read response failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("status code not ok: %d", resp.StatusCode)
	}

	return conn, nil
}

func (c *client) PacketConn(host string) (net.PacketConn, error) {
	return c.dialer.PacketConn(host)
}
