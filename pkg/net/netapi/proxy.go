package netapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync/atomic"
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
	AddressDispatcher
	io.Closer
}

type AddressDispatcher interface {
	Dispatch(context.Context, Address) (Address, error)
}

type StreamProxy interface {
	Conn(context.Context, Address) (net.Conn, error)
}

type PacketProxy interface {
	PacketConn(context.Context, Address) (net.PacketConn, error)
}

// ContextPacketWriter optionally binds datagram preparation (including DNS)
// to a caller. It does not change the established PacketConn's lifetime.
type ContextPacketWriter interface {
	WriteToContext(context.Context, []byte, net.Addr) (int, error)
}

type PingProxy interface {
	Ping(context.Context, Address) (uint64, error)
}

// IsBlockError recognizes a policy marker anywhere in a wrapped or joined error
// tree. An outer dial/read error must not hide an inner access-policy rejection.
func IsBlockError(err error) bool {
	for err != nil {
		if netErr, ok := err.(*net.OpError); ok {
			if netErr == nil {
				return false
			}
			if netErr.Op == "block" {
				return true
			}
		}
		// Preserve custom As implementations as well as ordinary unwrap chains.
		if _, ok := err.(interface{ As(any) bool }); ok {
			if netErr, ok := errors.AsType[*net.OpError](err); ok && netErr != nil && netErr.Op == "block" {
				return true
			}
		}
		switch value := err.(type) {
		case interface{ Unwrap() []error }:
			return slices.ContainsFunc(value.Unwrap(), IsBlockError)
		case interface{ Unwrap() error }:
			err = value.Unwrap()
		default:
			return false
		}
	}
	return false
}

func LogLevel(err error) slog.Level {
	if IsBlockError(err) {
		return slog.LevelDebug
	}

	return slog.LevelError
}

var _ AddressDispatcher = EmptyDispatch{}

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
	p atomic.Pointer[Proxy]
}

func (d *DynamicProxy) Conn(ctx context.Context, a Address) (net.Conn, error) {
	return (*d.p.Load()).Conn(ctx, a)
}

func (d *DynamicProxy) PacketConn(ctx context.Context, a Address) (net.PacketConn, error) {
	return (*d.p.Load()).PacketConn(ctx, a)
}

func (d *DynamicProxy) Ping(ctx context.Context, a Address) (uint64, error) {
	return (*d.p.Load()).Ping(ctx, a)
}

func (d *DynamicProxy) Dispatch(ctx context.Context, a Address) (Address, error) {
	return (*d.p.Load()).Dispatch(ctx, a)
}

func (d *DynamicProxy) Close() error {
	return (*d.p.Load()).Close()
}

func (d *DynamicProxy) Set(p Proxy) { d.p.Store(&p) }

func NewDynamicProxy(p Proxy) *DynamicProxy {
	d := &DynamicProxy{}
	d.Set(p)
	return d
}
