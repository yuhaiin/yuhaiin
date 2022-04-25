package websocket

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"golang.org/x/net/websocket"
)

type client struct {
	wsConfig  *websocket.Config
	tlsConfig *tls.Config
	dialer    proxy.Proxy
}

func New(cf *node.PointProtocol_Websocket) node.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {

		header := http.Header{}
		header.Add("Host", cf.Websocket.Host)

		protocol := "ws"
		tls := node.ParseTLSConfig(cf.Websocket.Tls)
		if tls != nil {
			//tls
			protocol = "wss"
		}

		uri, err := url.Parse(fmt.Sprintf("%s://%s%s", protocol, cf.Websocket.Host, getNormalizedPath(cf.Websocket.Path)))
		if err != nil {
			return nil, fmt.Errorf("websocket parse uri failed: %w", err)
		}

		return &client{
			wsConfig: &websocket.Config{
				Location: uri, Origin: &url.URL{},
				Version: websocket.ProtocolVersionHybi13,
				Header:  header,
			},
			tlsConfig: tls,
			dialer:    dialer,
		}, nil

	}
}

func (c *client) Conn(h string) (net.Conn, error) {
	conn, err := c.dialer.Conn(h)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	if c.tlsConfig != nil {
		conn = tls.Client(conn, c.tlsConfig)
	}

	wsconn, err := websocket.NewClient(c.wsConfig, conn)
	if err != nil {
		return nil, fmt.Errorf("websocket new client failed: %w", err)
	}

	return &connection{Conn: wsconn, laddr: conn.LocalAddr, raddr: conn.RemoteAddr}, nil
}

func (c *client) PacketConn(host string) (net.PacketConn, error) {
	return c.dialer.PacketConn(host)
}

type connection struct {
	*websocket.Conn
	laddr, raddr func() net.Addr
}

func (c *connection) RemoteAddr() net.Addr {
	return c.raddr()
}

func (c *connection) LocalAddr() net.Addr {
	return c.laddr()
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

/*
type Client struct {
	uri string
	p   proxy.Proxy

	header http.Header
	dialer *websocket.Dialer
}

func NewWebsocket(config *node.PointProtocol_Websocket) node.WrapProxy {
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

// connection is a wrapper for net.Conn over WebSocket connection.
type connection struct {
	*websocket.Conn
	reader io.Reader
}

// Read implements net.Conn.Read()
func (c *connection) Read(b []byte) (int, error) {
	for {
		reader, err := c.getReader()
		if err != nil {
			return 0, err
		}

		nBytes, err := reader.Read(b)
		if errors.Is(err, io.EOF) {
			c.reader = nil
			continue
		}
		return nBytes, err
	}
}

func (c *connection) ReadFrom(r io.Reader) (int64, error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)

	n := int64(0)
	for {
		nr, er := r.Read(buf)
		n += int64(nr)
		_, err := c.Write(buf[:nr])
		if err != nil {
			return n, err
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return n, nil
			}
			return n, er
		}
	}
}

func (c *connection) getReader() (io.Reader, error) {
	if c.reader != nil {
		return c.reader, nil
	}

	_, reader, err := c.Conn.NextReader()
	if err != nil {
		return nil, err
	}
	c.reader = reader
	return reader, nil
}

// Write implements io.Writer.
func (c *connection) Write(b []byte) (int, error) {
	err := c.Conn.WriteMessage(websocket.BinaryMessage, b)
	return len(b), err
}

func (c *connection) WriteTo(w io.Writer) (int64, error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)

	n := int64(0)
	for {
		nr, er := c.Read(buf)
		if nr > 0 {
			nw, err := w.Write(buf[:nr])
			n += int64(nw)
			if err != nil {
				return n, err
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return n, nil
			}
			return n, er
		}
	}
}

func (c *connection) Close() error {
	defer c.Conn.Close()
	return c.Conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5))
}

// func (c *connection) LocalAddr() net.Addr {
// 	return c.Conn.LocalAddr()
// }

// func (c *connection) RemoteAddr() net.Addr {
// 	return c.remoteAddr
// }

func (c *connection) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// func (c *connection) SetReadDeadline(t time.Time) error {
// return c.conn.SetReadDeadline(t)
// }

// func (c *connection) SetWriteDeadline(t time.Time) error {
// return c.conn.SetWriteDeadline(t)
// }
*/
