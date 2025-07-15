package netapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
)

type Process struct {
	Path string
	Pid  uint
	Uid  uint
}

type ProcessDumper interface {
	ProcessName(network string, src, dst Address) (Process, error)
}

type Proxy interface {
	StreamProxy
	PacketProxy
	PingProxy
	Dispatch(context.Context, Address) (Address, error)
	io.Closer
}

type StreamProxy interface {
	Conn(context.Context, Address) (net.Conn, error)
}

type PacketProxy interface {
	PacketConn(context.Context, Address) (net.PacketConn, error)
}

type PingProxy interface {
	Ping(context.Context, Address) (uint64, error)
}

func IsBlockError(err error) bool {
	netErr := &net.OpError{}

	if errors.As(err, &netErr) {
		return netErr.Op == "block"
	}

	return false
}

func LogLevel(err error) slog.Level {
	if IsBlockError(err) {
		return slog.LevelDebug
	}

	return slog.LevelError
}

type EmptyDispatch struct{}

func (EmptyDispatch) Dispatch(_ context.Context, a Address) (Address, error) { return a, nil }

type errProxy struct {
	EmptyDispatch
	error
}

func NewErrProxy(err error) Proxy                                              { return &errProxy{error: err} }
func (e errProxy) Conn(context.Context, Address) (net.Conn, error)             { return nil, e.error }
func (e errProxy) PacketConn(context.Context, Address) (net.PacketConn, error) { return nil, e.error }
func (e errProxy) Ping(context.Context, Address) (uint64, error)               { return 0, e.error }
func (errProxy) Close() error                                                  { return nil }

type DynamicProxy struct {
	p  Proxy
	mu sync.RWMutex
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

func (d *DynamicProxy) Ping(ctx context.Context, a Address) (uint64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.p.Ping(ctx, a)
}

func (d *DynamicProxy) Dispatch(ctx context.Context, a Address) (Address, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.p.Dispatch(ctx, a)
}

func (d *DynamicProxy) Close() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.p.Close()
}

func (d *DynamicProxy) Set(p Proxy) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.p = p
}

func NewDynamicProxy(p Proxy) *DynamicProxy { return &DynamicProxy{p: p} }
