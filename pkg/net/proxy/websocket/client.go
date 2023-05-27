package websocket

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

type client struct {
	wsConfig *websocket.Config
	proxy.Proxy
}

func New(cf *protocol.Protocol_Websocket) protocol.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {

		return &client{
			&websocket.Config{
				Host:      cf.Websocket.Host,
				Path:      getNormalizedPath(cf.Websocket.Path),
				OriginUrl: cf.Websocket.Host,
			},
			dialer,
		}, nil
	}
}

func (c *client) Conn(ctx context.Context, h proxy.Address) (net.Conn, error) {
	conn, err := c.Proxy.Conn(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	ctx, cancel := context.WithCancel(context.TODO())

	return &earlyConn{config: c.wsConfig, Conn: conn, handshakeCtx: ctx, handshakeDone: cancel}, nil
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
	config *websocket.Config

	handshakeMu   sync.Mutex
	handshakeCtx  context.Context
	handshakeDone func()

	deadline *time.Timer
}

func (e *earlyConn) Read(b []byte) (int, error) {
	if !e.handclasp {
		<-e.handshakeCtx.Done()
	}

	return e.Conn.Read(b)
}

func (e *earlyConn) Close() error {
	e.handshakeDone()
	return e.Conn.Close()
}

func (e *earlyConn) Write(b []byte) (int, error) {
	if e.handclasp {
		return e.Conn.Write(b)
	}

	return e.handshake(b)
}

func (e *earlyConn) handshake(b []byte) (int, error) {
	e.handshakeMu.Lock()
	defer e.handshakeMu.Unlock()

	if e.handclasp {
		return e.Conn.Write(b)
	}

	defer e.handshakeDone()

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

func (c *earlyConn) SetDeadline(t time.Time) error {
	if c.deadline == nil {
		if !t.IsZero() {
			c.deadline = time.AfterFunc(t.Sub(time.Now()), func() { c.handshakeDone() })
		}
		return nil
	}

	if t.IsZero() {
		c.deadline.Stop()
	} else {
		c.deadline.Reset(t.Sub(time.Now()))
	}

	c.Conn.SetDeadline(t)
	return nil
}

func (c *earlyConn) SetReadDeadline(t time.Time) error {
	c.SetDeadline(t)
	return c.Conn.SetReadDeadline(t)
}

func (c *earlyConn) SetWriteDeadline(t time.Time) error {
	c.SetDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}
