package websocket

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	ynet "github.com/Asutorufa/yuhaiin/pkg/utils/net"
)

type client struct {
	wsConfig *websocket.Config
	netapi.Proxy
}

func init() {
	point.RegisterProtocol(NewClient)
}

func NewClient(cf *protocol.Protocol_Websocket) point.WrapProxy {
	return func(dialer netapi.Proxy) (netapi.Proxy, error) {

		return &client{
			&websocket.Config{
				Host: cf.Websocket.Host,
				Path: getNormalizedPath(cf.Websocket.Path),
			},
			dialer,
		}, nil
	}
}

func (c *client) Conn(ctx context.Context, h netapi.Address) (net.Conn, error) {
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

	var SecWebSocketKey string
	if len(b) != 0 && len(b) <= 2048 {
		SecWebSocketKey = base64.RawStdEncoding.EncodeToString(b)
	}

	var earlyDataSupport bool
	conn, err := e.config.NewClient(SecWebSocketKey, e.Conn,
		func(r *http.Request) error {
			r.Header.Set("User-Agent", ynet.UserAgents[rand.IntN(ynet.UserAgentLength)])
			r.Header.Set("Sec-Fetch-Dest", "websocket")
			r.Header.Set("Sec-Fetch-Mode", "websocket")
			r.Header.Set("Pragma", "no-cache")
			if SecWebSocketKey != "" {
				r.Header.Set("early_data", "base64")
			}
			return nil
		},
		func(r *http.Response) error {
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
	c.setDeadline(t)
	return c.Conn.SetDeadline(t)
}

func (c *earlyConn) setDeadline(t time.Time) {
	if c.deadline == nil {
		if !t.IsZero() {
			c.deadline = time.AfterFunc(time.Until(t), func() { c.handshakeDone() })
		}
		return
	}

	if t.IsZero() {
		c.deadline.Stop()
	} else {
		c.deadline.Reset(time.Until(t))
	}
}

func (c *earlyConn) SetReadDeadline(t time.Time) error {
	c.setDeadline(t)
	return c.Conn.SetReadDeadline(t)
}

func (c *earlyConn) SetWriteDeadline(t time.Time) error {
	c.setDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}
