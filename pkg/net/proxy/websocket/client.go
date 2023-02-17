package websocket

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"sync"

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
				Host:      cf.Websocket.Host,
				Path:      getNormalizedPath(cf.Websocket.Path),
				OriginUrl: cf.Websocket.Host,
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

	return &earlyConn{config: c.wsConfig, Conn: conn, handshakeSignal: make(chan struct{})}, nil
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

type earlyConn struct {
	handclasp bool
	net.Conn
	config          *websocket.Config
	handshakeLock   sync.Mutex
	handshakeSignal chan struct{}
	closed          bool
}

func (e *earlyConn) Read(b []byte) (int, error) {
	if !e.handclasp {
		<-e.handshakeSignal
	}

	return e.Conn.Read(b)
}

func (e *earlyConn) Close() error {
	e.handshakeLock.Lock()
	defer e.handshakeLock.Unlock()
	if e.closed {
		return nil
	}

	e.closed = true
	err := e.Conn.Close()
	select {
	case <-e.handshakeSignal:
	default:
		close(e.handshakeSignal)
	}

	return err
}

func (e *earlyConn) Write(b []byte) (int, error) {
	if e.closed {
		return 0, net.ErrClosed
	}

	if e.handclasp {
		return e.Conn.Write(b)
	}

	return e.handshake(b)
}

func (e *earlyConn) handshake(b []byte) (int, error) {
	e.handshakeLock.Lock()
	defer e.handshakeLock.Unlock()

	if e.closed {
		return 0, net.ErrClosed
	}

	if e.handclasp {
		return e.Conn.Write(b)
	}

	defer close(e.handshakeSignal)

	header := http.Header{}

	header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0")
	header.Set("Sec-Fetch-Dest", "websocket")
	header.Set("Sec-Fetch-Mode", "websocket")
	header.Set("Pragma", "no-cache")
	var SecWebSocketKey string

	if len(b) != 0 && len(b) <= 2048 {
		header.Set("early_data", "base64")
		SecWebSocketKey = base64.RawStdEncoding.EncodeToString(b)
	}

	var earlyDataSupport bool
	conn, err := websocket.NewClient(e.config, SecWebSocketKey,
		header, e.Conn, func(r *http.Response) error {
			earlyDataSupport = r.Header.Get("early_data") == "true"
			return nil
		})
	if err != nil {
		return 0, fmt.Errorf("websocket handshake failed: %w", err)
	}
	e.Conn = conn

	e.handclasp = true

	if !earlyDataSupport {
		return conn.Write(b)
	}

	return len(b), nil
}
