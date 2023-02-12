package websocket

import (
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"golang.org/x/net/websocket"
)

type client struct {
	wsConfig *websocket.Config
	proxy.EmptyDispatch
	dialer proxy.Proxy
}

func New(cf *protocol.Protocol_Websocket) protocol.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {
		header := http.Header{}
		header.Add("Host", cf.Websocket.Host)

		var scheme string
		if cf.Websocket.TlsEnabled {
			scheme = "wss"
		} else {
			scheme = "ws"
		}

		uri, err := url.Parse(fmt.Sprintf("%s://%s%s", scheme, cf.Websocket.Host, getNormalizedPath(cf.Websocket.Path)))
		if err != nil {
			return nil, fmt.Errorf("websocket parse uri failed: %w", err)
		}

		return &client{
			wsConfig: &websocket.Config{
				Location: uri,
				Origin:   &url.URL{},
				Version:  websocket.ProtocolVersionHybi13,
				Header:   header,
			},
			dialer: dialer,
		}, nil

	}
}

func (c *client) Conn(h proxy.Address) (net.Conn, error) {
	conn, err := c.dialer.Conn(h)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	wsconn, err := websocket.NewClient(c.wsConfig, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("websocket new client failed: %w", err)
	}

	return &Connection{wsconn, conn}, nil
}

func (c *client) PacketConn(host proxy.Address) (net.PacketConn, error) {
	return c.dialer.PacketConn(host)
}

type Connection struct {
	*websocket.Conn
	RawConn net.Conn
}

func (c *Connection) RemoteAddr() net.Addr { return c.RawConn.RemoteAddr() }
func (c *Connection) LocalAddr() net.Addr  { return c.RawConn.LocalAddr() }

func getNormalizedPath(path string) string {
	if path == "" {
		return "/"
	}
	if path[0] != '/' {
		return "/" + path
	}
	return path
}
