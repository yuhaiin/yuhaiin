package proxy

import (
	"io"
)

type Server interface {
	io.Closer
}

var _ Server = (*EmptyServer)(nil)

type EmptyServer struct{}

func (e *EmptyServer) Close() error { return nil }
