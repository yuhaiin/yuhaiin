package interfaces

import "net"

type Server interface {
	SetTCPConn(func(string) (net.Conn, error))
	UpdateListen(host string) error
	Close() error
}
