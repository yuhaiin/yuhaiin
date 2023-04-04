package server

import (
	"context"
	"io"
	"net"
)

type Server interface {
	io.Closer
}

type DNSServer interface {
	Server
	HandleUDP(context.Context, net.PacketConn) error
	HandleTCP(context.Context, net.Conn) error
	Do(context.Context, []byte) ([]byte, error)
}

var EmptyDNSServer DNSServer = &emptyDNSServer{}

type emptyDNSServer struct{}

func (e *emptyDNSServer) Close() error                                    { return nil }
func (e *emptyDNSServer) HandleUDP(context.Context, net.PacketConn) error { return io.EOF }
func (e *emptyDNSServer) HandleTCP(context.Context, net.Conn) error       { return io.EOF }
func (e *emptyDNSServer) Do(context.Context, []byte) ([]byte, error)      { return nil, io.EOF }
