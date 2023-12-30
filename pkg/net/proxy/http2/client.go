package http2

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/net/http2"
)

type Client struct {
	client *clientConnPool
	netapi.Proxy
}

func init() {
	point.RegisterProtocol(NewClient)
}

func NewClient(config *protocol.Protocol_Http2) point.WrapProxy {
	return func(p netapi.Proxy) (netapi.Proxy, error) {

		if config.Http2.Concurrency < 1 {
			config.Http2.Concurrency = 1
		}

		cpool := &clientConnPool{
			dialer: p,
			conns:  make([]*entry, config.Http2.Concurrency),
			max:    uint64(config.Http2.Concurrency),
		}

		for i := range cpool.conns {
			cpool.conns[i] = &entry{}
		}

		return &Client{
			client: cpool,
			Proxy:  p,
		}, nil
	}
}

type entry struct {
	mu   sync.Mutex
	raw  net.Conn
	conn *http2.ClientConn
}

type clientConnPool struct {
	dialer netapi.Proxy
	conns  []*entry

	max     uint64
	current atomic.Uint64
}

func (c *clientConnPool) OpenStream(ctx context.Context) (uint64, net.Conn, *http2.ClientConn, error) {
	nowNumber := c.current.Add(1)

	conn := c.conns[nowNumber%(c.max)]

	cc := conn.conn

	if cc != nil {
		state := cc.State()
		if !state.Closed && !state.Closing {
			return nowNumber, conn.raw, cc, nil
		}
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.conn != nil {
		state := conn.conn.State()
		if !state.Closed && !state.Closing {
			return nowNumber, conn.raw, conn.conn, nil
		}
	}

	rawConn, err := c.dialer.Conn(ctx, netapi.EmptyAddr)
	if err != nil {
		return nowNumber, nil, nil, err
	}

	transport := &http2.Transport{
		DisableCompression: true,
		AllowHTTP:          true,
		ReadIdleTimeout:    time.Second * 30,
		MaxReadFrameSize:   pool.DefaultSize,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return rawConn, nil
		},
	}

	cc, err = transport.NewClientConn(rawConn)
	if err != nil {
		rawConn.Close()
		return nowNumber, nil, nil, err
	}

	conn.conn = cc
	conn.raw = rawConn

	return nowNumber, rawConn, cc, nil
}

func (c *Client) Conn(ctx context.Context, add netapi.Address) (net.Conn, error) {
	id, raw, clientConn, err := c.client.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("http2 get client conn failed: %w", err)
	}

	r, w := io.Pipe()

	respr := newReadCloser()

	h2conn := &http2Conn{
		piper:      r,
		pipew:      w,
		r:          respr,
		localAddr:  addr{addr: raw.LocalAddr().String(), id: id},
		remoteAddr: raw.RemoteAddr(),
	}

	go func() {
		resp, err := clientConn.RoundTrip(&http.Request{
			Method: http.MethodConnect,
			Body:   &wrapPipeReaderClose{r},
			URL:    &url.URL{Scheme: "https", Host: "localhost"},
		})
		if err != nil {
			r.CloseWithError(err)
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
	ctx  context.Context
	done context.CancelFunc
}

func newReadCloser() *readCloser {
	ctx, cancel := context.WithCancel(context.Background())
	return &readCloser{ctx: ctx, done: cancel}
}

func (r *readCloser) Close() error {
	if r.rc != nil {
		return r.rc.Close()
	}

	r.done()
	return nil
}

func (r *readCloser) SetReadCloser(rc io.ReadCloser) {
	r.rc = rc
	r.done()
}

func (r *readCloser) Read(b []byte) (int, error) {
	if r.rc == nil {
		<-r.ctx.Done()
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

type wrapPipeReaderClose struct {
	*io.PipeReader
}

func (w *wrapPipeReaderClose) Close() error { return w.PipeReader.CloseWithError(io.EOF) }
