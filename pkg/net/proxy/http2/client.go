package http2

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"golang.org/x/net/http2"
)

type Client struct {
	netapi.Proxy
	transport *http2.Transport
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(config *protocol.Http2, p netapi.Proxy) (netapi.Proxy, error) {
	if config.GetConcurrency() < 7 {
		config.SetConcurrency(10)
	}

	transport := &http2.Transport{
		DisableCompression: true,
		AllowHTTP:          true,
		ReadIdleTimeout:    time.Second * 30,
		MaxReadFrameSize:   pool.DefaultSize,
		IdleConnTimeout:    time.Minute,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return p.Conn(ctx, netapi.EmptyAddr)
		},
	}

	transport.ConnPool = newClientConnectionPool(transport, int(config.GetConcurrency()))

	return &Client{
		Proxy:     p,
		transport: transport,
	}, nil
}

func (c *Client) Conn(pctx context.Context, add netapi.Address) (net.Conn, error) {
	p1, p2 := pipe.Pipe()

	var localAddr net.Addr = netapi.EmptyAddr
	var remoteAddr net.Addr = netapi.EmptyAddr
	var ConnID string
	var conn *http2.ClientConn

	tract := &httptrace.ClientTrace{
		GotConn: func(gci httptrace.GotConnInfo) {
			localAddr = gci.Conn.LocalAddr()
			remoteAddr = gci.Conn.RemoteAddr()
		},
	}

	connected := make(chan struct{})
	defer close(connected)

	// we can't use parent ctx, the parent ctx will make body close
	// see: https://github.com/golang/net/blob/b4c86550a5be2d314b04727f13affd9bb07fcf46/http2/transport.go#L1569
	ctx, cancel := context.WithCancel(context.WithoutCancel(pctx))

	go func() {
		select {
		case <-pctx.Done():
			cancel()
		case <-connected:
		}
	}()

	hctx := httptrace.WithClientTrace(ctx, tract)
	hctx = WithGetClientConnInfo(hctx, func(connID uint64, streamID uint32, c *http2.ClientConn) {
		ConnID, conn = fmt.Sprintf("%d-%d", connID, streamID), c
	})

	// because Body is a ReadCloser, it's just need CloseRead
	// we show don't allow it close write
	req, err := http.NewRequestWithContext(hctx, http.MethodConnect, "https://localhost", io.NopCloser(p1))
	if err != nil {
		return nil, fmt.Errorf("new request failed: %w", err)
	}

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		_ = p1.Close()
		_ = p2.Close()
		if conn != nil {
			conn.SetDoNotReuse()
		}
		return nil, fmt.Errorf("round trip failed: %w", err)
	}

	go func() {
		defer cancel()
		_, err := relay.Copy(p1, &bodyReader{resp.Body})

		if err != nil && err != io.EOF && err != io.ErrClosedPipe &&
			// https://github.com/golang/net/blob/b4c86550a5be2d314b04727f13affd9bb07fcf46/http2/transport.go#L698
			err.Error() != "http2: client conn is closed" &&
			// https://github.com/golang/net/blob/b4c86550a5be2d314b04727f13affd9bb07fcf46/http2/transport.go#L1267
			err.Error() != "http2: client connection lost" {
			log.Error("relay client response body to pipe failed", "err", err, "addr", add)
		}
		_ = p1.Close()
		err = resp.Body.Close()
		if err != nil {
			log.Error("close resp body failed", "err", err)
		}
	}()

	p2.SetLocalAddr(addr{addr: localAddr.String(), id: ConnID})
	p2.SetRemoteAddr(remoteAddr)

	return p2, nil
}

func (c *Client) Close() error {
	c.transport.CloseIdleConnections()
	return nil
}

type clientConnEntry struct {
	id    uint64
	count *atomic.Uint32
}
type clientConnectionPool struct {
	mu          sync.Mutex
	concurrency int
	t           *http2.Transport
	count       atomic.Uint64
	store       map[*http2.ClientConn]clientConnEntry
}

func newClientConnectionPool(t *http2.Transport, concurrency int) *clientConnectionPool {
	return &clientConnectionPool{
		t:           t,
		concurrency: concurrency,
		store:       make(map[*http2.ClientConn]clientConnEntry, 10),
	}
}

func (c *clientConnectionPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, v := range c.store {
		state := k.State()

		if state.Closed || state.Closing {
			delete(c.store, k)
			k.SetDoNotReuse()
			continue
		}

		if state.StreamsActive+state.StreamsPending < c.concurrency {
			ContextGetClientConnInfo(req.Context(), v.id, v.count.Add(1), k)
			return k, nil
		}
	}

	conn, err := c.t.DialTLSContext(req.Context(), "tcp", addr, nil)
	if err != nil {
		return nil, err
	}

	cc, err := c.t.NewClientConn(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	entry := clientConnEntry{
		id:    c.count.Add(1),
		count: new(atomic.Uint32),
	}
	c.store[cc] = entry

	log.Info("new client connection", "id", entry.id)

	ContextGetClientConnInfo(req.Context(), entry.id, entry.count.Add(1), cc)

	return cc, nil
}

func (c *clientConnectionPool) MarkDead(hc *http2.ClientConn) {
	c.mu.Lock()
	id, ok := c.store[hc]
	if ok {
		delete(c.store, hc)
	}
	c.mu.Unlock()

	log.Info("mark dead", "last idle", hc.State().LastIdle, "id", id.id)
}

type clientConnInfoKey struct{}

func ContextGetClientConnInfo(ctx context.Context, connID uint64, streamID uint32, conn *http2.ClientConn) {
	z, ok := ctx.Value(clientConnInfoKey{}).(func(connID uint64, streamID uint32, conn *http2.ClientConn))
	if ok {
		z(connID, streamID, conn)
	}
}

func WithGetClientConnInfo(ctx context.Context, f func(connID uint64, streamID uint32, conn *http2.ClientConn)) context.Context {
	return context.WithValue(ctx, clientConnInfoKey{}, f)
}
