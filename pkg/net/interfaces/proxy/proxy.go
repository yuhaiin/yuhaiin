package proxy

import "net"

type Proxy interface {
	StreamProxy
	PacketProxy
}

type StreamProxy interface {
	Conn(host string) (net.Conn, error)
}

type PacketProxy interface {
	PacketConn(host string) (net.PacketConn, error)
}

type errProxy struct{ error }

func NewErrProxy(err error) Proxy                            { return &errProxy{err} }
func (e errProxy) Conn(string) (net.Conn, error)             { return nil, e.error }
func (e errProxy) PacketConn(string) (net.PacketConn, error) { return nil, e.error }
