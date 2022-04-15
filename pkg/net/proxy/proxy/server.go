package proxy

import "io"

type Server interface {
	SetProxy(Proxy)
	SetServer(host string) error
	io.Closer
}

var _ Server = (*EmptyServer)(nil)

type EmptyServer struct{}

func (e *EmptyServer) SetProxy(Proxy)         {}
func (e *EmptyServer) SetServer(string) error { return nil }
func (e *EmptyServer) Close() error           { return nil }
