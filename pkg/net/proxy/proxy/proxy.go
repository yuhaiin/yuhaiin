package proxy

import (
	"net"
	"time"
)

type Proxy interface {
	Conn(string) (net.Conn, error)
	PacketConn(string) (net.PacketConn, error)
}

type DefaultProxy struct {
}

func (d *DefaultProxy) Conn(s string) (net.Conn, error) {
	return net.DialTimeout("tcp", s, 15*time.Second)
}
func (d *DefaultProxy) PacketConn(string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}
