package proxy

import "net"

type Server interface {
	UpdateListen(host string) error
	Close() error
}

type TCPServer interface {
	Server
	SetTCPConn(func(string) (net.Conn, error))
}

type UDPServer interface {
	Server
	SetUDPConn(func(string) (*net.UDPConn, error))
}
