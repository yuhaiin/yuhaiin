package http2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

type Client struct {
	netapi.Proxy
	pool *clientConnectionPool
}

type Config struct {
	Concurrency int32 `json:"concurrency"`
}

func init() {
	register.RegisterContractPoint("http2", func(config contractnode.Concurrency, p netapi.Proxy) (netapi.Proxy, error) {
		return NewClient(Config{Concurrency: config.Concurrency}, p)
	})
}

func NewClient(config Config, p netapi.Proxy) (netapi.Proxy, error) {
	if config.Concurrency < 7 {
		config.Concurrency = 10
	}

	// This proxy speaks only HTTP/2 prior knowledge over plaintext.
	// Leaving HTTP/1 and TLS HTTP/2 unset is intentional.
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)

	transport := &http.Transport{
		DisableCompression: true,
		IdleConnTimeout:    time.Minute,
		Protocols:          protocols,
		HTTP2: &http.HTTP2Config{
			MaxReadFrameSize: pool.DefaultSize,
			SendPingTimeout:  30 * time.Second,
		},
	}

	return &Client{
		Proxy: p,
		pool:  newClientConnectionPool(transport, p, int(config.Concurrency)),
	}, nil
}

var idg atomic.Uint64

func init() {
	idg.Store(uint64(time.Now().Unix()))
}

func (c *Client) Conn(pctx context.Context, add netapi.Address) (net.Conn, error) {
	p1, p2 := pipe.Pipe()

	// The request body remains open for the lifetime of the tunneled stream.
	// Do not let the parent context close it while the response side is still
	// being relayed.
	ctx, cancel := context.WithCancel(context.WithoutCancel(pctx))
	stopCancel := context.AfterFunc(pctx, cancel)
	defer stopCancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://localhost", io.NopCloser(p1))
	if err != nil {
		_ = p1.Close()
		_ = p2.Close()
		return nil, fmt.Errorf("new request failed: %w", err)
	}

	entry, err := c.pool.get(ctx, netapi.GetContext(ctx).ConnOptions().IsUdp())
	if err != nil {
		_ = p1.Close()
		_ = p2.Close()
		return nil, fmt.Errorf("get http2 connection failed: %w", err)
	}

	resp, err := entry.conn.RoundTrip(request)
	if err != nil {
		c.pool.remove(entry)
		_ = entry.conn.Close()
		_ = p1.Close()
		_ = p2.Close()
		return nil, fmt.Errorf("round trip failed: %w", err)
	}

	p2.SetLocalAddr(addr{addr: entry.raw.LocalAddr().String(), id: idg.Add(1)})
	p2.SetRemoteAddr(entry.raw.RemoteAddr())

	go func() {
		defer cancel()

		_, relayErr := relay.Copy(p1, &bodyReader{resp.Body})
		if relayErr != nil && !ignoreError(relayErr) {
			log.Error("relay client response body to pipe failed", "err", relayErr, "addr", add)
		}
		_ = p1.Close()
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error("close resp body failed", "err", closeErr)
		}
	}()

	return p2, nil
}

func (c *Client) Close() error {
	return c.pool.close()
}

func ignoreError(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		strings.Contains(err.Error(), "http2: client connection force closed") ||
		strings.Contains(err.Error(), "unexpected EOF")
}

type pooledConn struct {
	conn *http.ClientConn
	raw  net.Conn
}

type clientConnectionPool struct {
	transport   *http.Transport
	dialer      netapi.Proxy
	concurrency int

	streamStore   connList
	datagramStore connList
}

func newClientConnectionPool(transport *http.Transport, dialer netapi.Proxy, concurrency int) *clientConnectionPool {
	return &clientConnectionPool{
		transport:     transport,
		dialer:        dialer,
		concurrency:   concurrency,
		streamStore:   newConnList(),
		datagramStore: newConnList(),
	}
}

func (p *clientConnectionPool) get(ctx context.Context, datagram bool) (*pooledConn, error) {
	store := &p.streamStore
	if datagram {
		store = &p.datagramStore
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	for i := 0; i < len(store.conns); i++ {
		entry := store.conns[i]
		if entry.conn.Err() != nil {
			store.removeLocked(entry)
			_ = entry.conn.Close()
			i--
			continue
		}

		if entry.conn.InFlight() >= p.concurrency {
			continue
		}

		if err := entry.conn.Reserve(); err == nil {
			return entry, nil
		}

		// Reserve also observes asynchronous states such as GOAWAY that Err
		// does not expose. Do not leave such connections in the pool to be
		// scanned on every subsequent request.
		store.removeLocked(entry)
		_ = entry.conn.Close()
		i--
	}

	entry, err := p.newConnection(ctx)
	if err != nil {
		return nil, err
	}

	if err := entry.conn.Reserve(); err != nil {
		_ = entry.conn.Close()
		return nil, err
	}

	store.conns = append(store.conns, entry)
	return entry, nil
}

func (p *clientConnectionPool) newConnection(ctx context.Context) (*pooledConn, error) {
	// NewClientConn obtains its net.Conn through DialContext. Clone the
	// configuration so this connection can install a private DialContext that
	// captures its raw connection without racing with other pool entries.
	transport := p.transport.Clone()

	var raw net.Conn
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		var err error
		raw, err = p.dialer.Conn(ctx, netapi.EmptyAddr)
		return raw, err
	}

	conn, err := transport.NewClientConn(ctx, "http", "localhost:80")
	if err != nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, err
	}
	if raw == nil {
		_ = conn.Close()
		return nil, errors.New("http2 connection dial returned no net.Conn")
	}

	return &pooledConn{conn: conn, raw: raw}, nil
}

func (p *clientConnectionPool) remove(entry *pooledConn) {
	for _, store := range []*connList{&p.streamStore, &p.datagramStore} {
		store.mu.Lock()
		store.removeLocked(entry)
		store.mu.Unlock()
	}
}

func (p *clientConnectionPool) close() error {
	var err error
	for _, store := range []*connList{&p.streamStore, &p.datagramStore} {
		store.mu.Lock()
		conns := append([]*pooledConn(nil), store.conns...)
		store.conns = nil
		store.mu.Unlock()

		for _, entry := range conns {
			err = errors.Join(err, entry.conn.Close())
		}
	}
	return err
}

type connList struct {
	mu    sync.Mutex
	conns []*pooledConn
}

func newConnList() connList {
	return connList{}
}

func (c *connList) removeLocked(entry *pooledConn) {
	for i, candidate := range c.conns {
		if candidate == entry {
			c.conns = append(c.conns[:i], c.conns[i+1:]...)
			return
		}
	}
}

type bodyReader struct {
	io.ReadCloser
}

func NewBodyReader(r io.ReadCloser) io.ReadCloser {
	return &bodyReader{ReadCloser: r}
}

type addr struct {
	addr string
	id   uint64
}

func (addr) Network() string  { return "tcp" }
func (a addr) String() string { return fmt.Sprintf("http2.v2-%d-2%v", a.id, a.addr) }
