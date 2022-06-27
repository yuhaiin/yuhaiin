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
