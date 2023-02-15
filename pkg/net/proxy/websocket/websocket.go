package websocket

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

type client struct {
	wsConfig *websocket.Config
	proxy.EmptyDispatch
	dialer proxy.Proxy
}

func New(cf *protocol.Protocol_Websocket) protocol.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {

		return &client{
			wsConfig: &websocket.Config{
				Host:    cf.Websocket.Host,
				Path:    getNormalizedPath(cf.Websocket.Path),
				Version: websocket.ProtocolVersionHybi13,
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

	return wsconn, nil
}

func (c *client) PacketConn(host proxy.Address) (net.PacketConn, error) {
	return c.dialer.PacketConn(host)
}

func getNormalizedPath(path string) string {
	if path == "" {
		return "/"
	}
	if path[0] != '/' {
		return "/" + path
	}
	return path
}
