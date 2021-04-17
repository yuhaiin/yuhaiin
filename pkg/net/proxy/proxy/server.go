package proxy

import "net"

type Server interface {
	SetProxy(Proxy)
	UpdateListen(host string) error
	Close() error
}

type Handle interface {
	TCP(net.Conn)
	UDP(net.PacketConn)
}
