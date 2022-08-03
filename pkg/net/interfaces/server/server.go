package server

import (
	"io"
	"net"
)

type Server interface {
	io.Closer
}

type wrapServer struct {
	c func() error
}

func (w *wrapServer) Close() error {
	return w.c()
}

func WrapClose(c func() error) Server {
	return &wrapServer{c: c}
}

type DNSServer interface {
	Server
	HandleUDP(net.PacketConn) error
	HandleTCP(net.Conn) error
}

var EmptyDNSServer DNSServer = &emptyDNSServer{}

type emptyDNSServer struct{}

func (e *emptyDNSServer) Close() error                   { return nil }
func (e *emptyDNSServer) HandleUDP(net.PacketConn) error { return io.EOF }
func (e *emptyDNSServer) HandleTCP(net.Conn) error       { return io.EOF }
