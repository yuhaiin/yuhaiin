package proxy

import (
	"io"
	"net"
)

type Server interface {
	io.Closer
}

var _ Server = (*EmptyServer)(nil)

type EmptyServer struct{}

func (e *EmptyServer) Close() error { return nil }

func (e *EmptyServer) Addr() net.Addr { return &net.TCPAddr{} }
