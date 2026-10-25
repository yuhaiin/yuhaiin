package node

import (
	"context"
	"errors"
	"net"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const probeByteBudget int64 = 64 << 10

var errProbeByteBudget = errors.New("probe byte allowance reached")

type probeBudgetProxy struct {
	netapi.Proxy
	remaining atomic.Int64
}

func newProbeBudgetProxy(p netapi.Proxy) *probeBudgetProxy {
	return newByteBudgetProxy(p, probeByteBudget)
}
func newByteBudgetProxy(p netapi.Proxy, limit int64) *probeBudgetProxy {
	b := &probeBudgetProxy{Proxy: p}
	b.remaining.Store(limit)
	return b
}
func (p *probeBudgetProxy) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	c, err := p.Proxy.Conn(ctx, a)
	if err != nil {
		return nil, err
	}
	return &probeBudgetConn{Conn: c, b: p}, nil
}
func (p *probeBudgetProxy) PacketConn(ctx context.Context, a netapi.Address) (net.PacketConn, error) {
	c, err := p.Proxy.PacketConn(ctx, a)
	if err != nil {
		return nil, err
	}
	return &probeBudgetPacket{PacketConn: c, b: p}, nil
}
func (p *probeBudgetProxy) claim(n int) int {
	for {
		left := p.remaining.Load()
		if left <= 0 {
			return 0
		}
		take := min(int64(n), left)
		if p.remaining.CompareAndSwap(left, left-take) {
			return int(take)
		}
	}
}

type probeBudgetConn struct {
	net.Conn
	b *probeBudgetProxy
}

func (c *probeBudgetConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n := c.b.claim(len(b))
	if n == 0 {
		return 0, errProbeByteBudget
	}
	got, err := c.Conn.Read(b[:n])
	c.b.remaining.Add(int64(n - got))
	return got, err
}
func (c *probeBudgetConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n := c.b.claim(len(b))
	if n == 0 {
		return 0, errProbeByteBudget
	}
	got, err := c.Conn.Write(b[:n])
	c.b.remaining.Add(int64(n - got))
	if got < len(b) && err == nil {
		return got, errProbeByteBudget
	}
	return got, err
}

type probeBudgetPacket struct {
	net.PacketConn
	b *probeBudgetProxy
}

func (c *probeBudgetPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n := c.b.claim(len(b))
	if n == 0 {
		return 0, nil, errProbeByteBudget
	}
	got, a, err := c.PacketConn.ReadFrom(b[:n])
	c.b.remaining.Add(int64(n - got))
	return got, a, err
}
func (c *probeBudgetPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	n := c.b.claim(len(b))
	if n < len(b) {
		c.b.remaining.Add(int64(n))
		return 0, errProbeByteBudget
	}
	got, err := c.PacketConn.WriteTo(b, a)
	c.b.remaining.Add(int64(n - got))
	return got, err
}
