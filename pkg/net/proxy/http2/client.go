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
	"github.com/Asutorufa/yuhaiin/pkg/utils/list"
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
	var (
		localAddr  net.Addr = netapi.EmptyAddr
		remoteAddr net.Addr = netapi.EmptyAddr
		ConnID     string
		conn       *http2.ClientConn

		tract = &httptrace.ClientTrace{
			GotConn: func(gci httptrace.GotConnInfo) {
				localAddr = gci.Conn.LocalAddr()
				remoteAddr = gci.Conn.RemoteAddr()
			},
		}

		p1, p2 = pipe.Pipe()

		// we can't use parent ctx, the parent ctx will make body close
		// see: https://github.com/golang/net/blob/b4c86550a5be2d314b04727f13affd9bb07fcf46/http2/transport.go#L1569
		ctx, cancel = context.WithCancel(context.WithoutCancel(pctx))
	)

	stopCancel := context.AfterFunc(pctx, cancel)
	defer stopCancel()

	hctx := httptrace.WithClientTrace(ctx, tract)
	hctx = WithGetClientConnInfo(hctx, func(connID uint64, streamID uint32, c *http2.ClientConn) {
		ConnID, conn = fmt.Sprintf("%p-%d", c, streamID), c
	})

	// because Body is a ReadCloser, it's just need CloseRead
	// we should don't allow it close write
	req, err := http.NewRequestWithContext(hctx,
		http.MethodConnect, "https://localhost", io.NopCloser(p1))
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
		if err != nil && !c.ignoreError(err) {
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

func (c *Client) ignoreError(err error) bool {
	if err != io.EOF && err != io.ErrClosedPipe &&
		// https://github.com/golang/net/blob/b4c86550a5be2d314b04727f13affd9bb07fcf46/http2/transport.go#L698
		err.Error() != "http2: client conn is closed" &&
		// https://github.com/golang/net/blob/b4c86550a5be2d314b04727f13affd9bb07fcf46/http2/transport.go#L1267
		err.Error() != "http2: client connection lost" {
		return false
	}

	return true
}

func (c *Client) Close() error {
	c.transport.CloseIdleConnections()
	return nil
}

type clientConnEntry struct {
	conn  *http2.ClientConn
	count *atomic.Uint32
}
type clientConnectionPool struct {
	t *http2.Transport

	smu         sync.Mutex
	streamStore *connList

	dmu           sync.Mutex
	datagramStore *connList
}

func newClientConnectionPool(t *http2.Transport, concurrency int) *clientConnectionPool {
	return &clientConnectionPool{
		t:             t,
		streamStore:   newConnList(concurrency),
		datagramStore: newConnList(concurrency),
	}
}

func (c *clientConnectionPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	var store *connList
	if netapi.GetContext(req.Context()).ConnOptions().IsUdp() {
		c.dmu.Lock()
		defer c.dmu.Unlock()
		store = c.datagramStore
	} else {
		c.smu.Lock()
		defer c.smu.Unlock()
		store = c.streamStore
	}

	if conn := store.Get(req); conn != nil {
		return conn, nil
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

	entry := &clientConnEntry{
		conn:  cc,
		count: new(atomic.Uint32),
	}
	store.Push(entry)
	ContextGetClientConnInfo(req.Context(), entry)

	return cc, nil
}

func (c *clientConnectionPool) MarkDead(hc *http2.ClientConn) {
	c.smu.Lock()
	c.streamStore.Remove(hc)
	c.smu.Unlock()

	c.dmu.Lock()
	c.datagramStore.Remove(hc)
	c.dmu.Unlock()
}

type clientConnInfoKey struct{}
type getClientConnInfo func(connID uint64, streamID uint32, conn *http2.ClientConn)

func ContextGetClientConnInfo(ctx context.Context, entry *clientConnEntry) {
	z, ok := ctx.Value(clientConnInfoKey{}).(getClientConnInfo)
	if ok {
		z(0, entry.count.Add(1), entry.conn)
	}
}

func WithGetClientConnInfo(ctx context.Context, f getClientConnInfo) context.Context {
	return context.WithValue(ctx, clientConnInfoKey{}, f)
}

type connList struct {
	maps           map[*http2.ClientConn]*list.Element[*clientConnEntry]
	list           *list.List[*clientConnEntry]
	maxConcurrency int
}

func newConnList(maxConcurrency int) *connList {
	return &connList{
		maxConcurrency: maxConcurrency,
		maps:           make(map[*http2.ClientConn]*list.Element[*clientConnEntry]),
		list:           list.New[*clientConnEntry](),
	}
}

func (c *connList) Push(entry *clientConnEntry) {
	c.maps[entry.conn] = c.list.PushFront(entry)
}

func (c *connList) Remove(conn *http2.ClientConn) {
	if elem, ok := c.maps[conn]; ok {
		c.removeElem(elem)
	}
}

func (c *connList) removeElem(entry *list.Element[*clientConnEntry]) {
	c.list.Remove(entry)
	delete(c.maps, entry.Value().conn)
}

func (c *connList) Get(req *http.Request) *http2.ClientConn {
	e := c.list.Front()

	for e != nil {
		conn := e.Value().conn
		state := conn.State()

		if state.Closed || state.Closing {
			conn.SetDoNotReuse()

			remove := e
			e = e.Next()

			c.removeElem(remove)
			continue
		}

		currentNum := state.StreamsActive + state.StreamsPending
		if currentNum >= c.maxConcurrency {
			e = e.Next()
			continue
		}

		ContextGetClientConnInfo(req.Context(), e.Value())

		if currentNum+1 < c.maxConcurrency {
			c.list.MoveToFront(e)
		} else {
			log.Info("client connection pool full", "currentNum", currentNum, "maxConcurrency", c.maxConcurrency, "ptr", fmt.Sprintf("%p", e.Value()))
			c.list.MoveToBack(e)
		}

		return conn
	}
	return nil
}
