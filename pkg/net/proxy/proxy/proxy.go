package proxy

import (
	"net"
	"time"
)

type Proxy interface {
	StreamProxy
	PacketProxy
}

type StreamProxy interface {
	Conn(string) (net.Conn, error)
}

type PacketProxy interface {
	PacketConn(string) (net.PacketConn, error)
}

type Default struct{}

func (d *Default) Conn(s string) (net.Conn, error) {
	return net.DialTimeout("tcp", s, 15*time.Second)
}
func (d *Default) PacketConn(string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}

type ErrProxy struct {
	err error
}

func NewErrProxy(err error) Proxy {
	return &ErrProxy{err: err}
}

func (e *ErrProxy) Conn(string) (net.Conn, error) {
	return nil, e.err
}

func (e *ErrProxy) PacketConn(string) (net.PacketConn, error) {
	return nil, e.err
}
