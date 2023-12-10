package netapi

import (
	"context"
	"net"
	"sync"
)

type EmptyDispatch struct{}

func (EmptyDispatch) Dispatch(_ context.Context, a Address) (Address, error) { return a, nil }

type errProxy struct {
	EmptyDispatch
	error
}

func NewErrProxy(err error) Proxy                                              { return &errProxy{error: err} }
func (e errProxy) Conn(context.Context, Address) (net.Conn, error)             { return nil, e.error }
func (e errProxy) PacketConn(context.Context, Address) (net.PacketConn, error) { return nil, e.error }

type DynamicProxy struct {
	mu sync.RWMutex
	p  Proxy
}

func (d *DynamicProxy) Conn(ctx context.Context, a Address) (net.Conn, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.p.Conn(ctx, a)
}

func (d *DynamicProxy) PacketConn(ctx context.Context, a Address) (net.PacketConn, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.p.PacketConn(ctx, a)
}

func (d *DynamicProxy) Dispatch(ctx context.Context, a Address) (Address, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.p.Dispatch(ctx, a)
}

func (d *DynamicProxy) Set(p Proxy) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.p = p
}

func NewDynamicProxy(p Proxy) *DynamicProxy { return &DynamicProxy{p: p} }
