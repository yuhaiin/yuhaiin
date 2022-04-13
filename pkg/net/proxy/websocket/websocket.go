package websocket

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/gorilla/websocket"
)

type Client struct {
	uri string
	p   proxy.Proxy

	header http.Header
	dialer *websocket.Dialer
}

func NewWebsocket(config *node.PointProtocol_Websocket) func(p proxy.Proxy) (proxy.Proxy, error) {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		c := &Client{p: p}

		dialer := &websocket.Dialer{
			NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return p.Conn(addr)
			},
		}

		protocol := "ws"
		tls := node.ParseTLSConfig(config.Websocket.Tls)
		if tls != nil {
			//tls
			protocol = "wss"
			dialer.TLSClientConfig = tls
		}

		header := http.Header{}
		header.Add("Host", config.Websocket.Host)
		c.header = header
		c.uri = fmt.Sprintf("%s://%s%s", protocol, config.Websocket.Host, getNormalizedPath(config.Websocket.Path))
		c.dialer = dialer

		return c, nil
	}
}

func (c *Client) Conn(string) (net.Conn, error) {
	cc, _, err := c.dialer.Dial(c.uri, c.header)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}
	return &connection{Conn: cc}, nil
}

func (c *Client) PacketConn(host string) (net.PacketConn, error) {
	return c.p.PacketConn(host)
}

var tlsSessionCache = tls.NewLRUClientSessionCache(128)

func getNormalizedPath(path string) string {
	if path == "" {
		return "/"
	}
	if path[0] != '/' {
		return "/" + path
	}
	return path
}
