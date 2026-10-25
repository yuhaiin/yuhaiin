package latency

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type probeConnections struct {
	mu     sync.Mutex
	closed bool
	conns  []*probeContextConn
}

func (p *probeConnections) bind(ctx context.Context, conn net.Conn) (net.Conn, error) {
	c := newProbeContextConn(ctx, conn)
	p.mu.Lock()
	if p.closed || len(p.conns) >= 16 {
		p.mu.Unlock()
		_ = c.Close()
		return nil, errors.New("probe connection lifetime ended or connection limit reached")
	}
	p.conns = append(p.conns, c)
	p.mu.Unlock()
	return c, nil
}
func (p *probeConnections) close() {
	p.mu.Lock()
	p.closed = true
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// HTTP transports detach their dial context from request cancellation. Bind
// actual I/O to the full probe lifetime so pacing/DNS/protocol wrappers cannot
// outlive a cancelled or duration-limited measurement.
func newProbeContextConn(ctx context.Context, conn net.Conn) *probeContextConn {
	c := &probeContextConn{Conn: conn}
	c.stop = context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()); c.closeTransport() })
	return c
}

type probeContextConn struct {
	net.Conn
	once sync.Once
	stop func() bool
	err  error
}

func (c *probeContextConn) closeTransport() { c.once.Do(func() { c.err = c.Conn.Close() }) }
func (c *probeContextConn) Close() error    { c.stop(); c.closeTransport(); return c.err }
