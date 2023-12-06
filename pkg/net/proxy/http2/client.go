package http2

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"golang.org/x/net/http2"
)

type Client struct {
	client *clientConnPool
	netapi.Proxy

	idg id.IDGenerator
}

func NewClient(config *protocol.Protocol_Http2) protocol.WrapProxy {
	return func(p netapi.Proxy) (netapi.Proxy, error) {
		transport := &http2.Transport{
			DisableCompression: true,
			AllowHTTP:          true,
			ReadIdleTimeout:    time.Second * 30,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return p.Conn(ctx, netapi.EmptyAddr)
			},
		}

		cpool := &clientConnPool{
			dialer:    p,
			transport: transport,
			conns:     [8]*entry{{}, {}, {}, {}, {}, {}, {}, {}},
		}

		transport.ConnPool = cpool

		return &Client{
			cpool,
			p,
			id.IDGenerator{},
		}, nil
	}
}

type entry struct {
	mu   sync.Mutex
	raw  net.Conn
	conn *http2.ClientConn
}
type clientConnPool struct {
	dialer    netapi.Proxy
	transport *http2.Transport
	conns     [8]*entry
}

func (c *clientConnPool) getClientConn(ctx context.Context) (net.Conn, *http2.ClientConn, error) {
	conn := c.conns[rand.Intn(8)]

	cc := conn.conn

	if cc != nil {
		state := cc.State()
		if !state.Closed && !state.Closing {
			return conn.raw, cc, nil
		}
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.conn != nil {
		state := conn.conn.State()
		if !state.Closed && !state.Closing {
			return conn.raw, conn.conn, nil
		}
	}

	rawConn, err := c.dialer.Conn(ctx, netapi.EmptyAddr)
	if err != nil {
		return nil, nil, err
	}
	cc, err = c.transport.NewClientConn(rawConn)
	if err != nil {
		rawConn.Close()
		return nil, nil, err
	}

	conn.conn = cc
	conn.raw = rawConn

	return rawConn, cc, nil
}
func (c *clientConnPool) GetClientConn(*http.Request, string) (*http2.ClientConn, error) {
	_, cc, err := c.getClientConn(context.TODO())
	return cc, err
}
func (c *clientConnPool) MarkDead(conn *http2.ClientConn) {
	conn.Close()
	conn.Shutdown(context.Background())
}

func (c *Client) Conn(ctx context.Context, add netapi.Address) (net.Conn, error) {
	raw, clientConn, err := c.client.getClientConn(ctx)
	if err != nil {
		return nil, fmt.Errorf("http2 get client conn failed: %w", err)
	}

	r, w := io.Pipe()

	respr := newReadCloser()

	h2conn := &http2Conn{
		w:          w,
		r:          respr,
		localAddr:  addr{addr: raw.LocalAddr().String(), id: c.idg.Generate()},
		remoteAddr: raw.RemoteAddr(),
	}

	go func() {
		resp, err := clientConn.RoundTrip(&http.Request{
			Method: http.MethodConnect,
			Body:   r,
			URL:    &url.URL{Scheme: "https", Host: "localhost"},
		})
		if err != nil {
			r.Close()
			h2conn.Close()
			log.Error("http2 do request failed:", "err", err)
			return
		}

		respr.SetReadCloser(resp.Body)
	}()

	return h2conn, nil
}

type readCloser struct {
	rc   io.ReadCloser
	once sync.Once
	wait chan struct{}
}

func newReadCloser() *readCloser {
	return &readCloser{wait: make(chan struct{})}
}

func (r *readCloser) Close() error {
	if r.rc != nil {
		return r.rc.Close()
	}

	r.once.Do(func() { close(r.wait) })
	return nil
}

func (r *readCloser) SetReadCloser(rc io.ReadCloser) {
	r.once.Do(func() {
		r.rc = rc
		close(r.wait)
	})
}

func (r *readCloser) Read(b []byte) (int, error) {
	if r.rc == nil {
		<-r.wait
		if r.rc == nil {
			return 0, io.EOF
		}
	}

	n, err := r.rc.Read(b)
	if err != nil {
		if strings.Contains(err.Error(), "http2: response body closed") {
			err = io.EOF
		}

		return n, err
	}

	return n, nil
}
