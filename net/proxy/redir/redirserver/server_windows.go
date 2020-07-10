//+build windows

package redirserver

import (
	"net"

	proxyI "github.com/Asutorufa/yuhaiin/net/proxy/interface"
)

type Server struct {
}

type Option struct {
	TcpConn func(string) (net.Conn, error)
}

func New(host string, modeOption ...func(*Option)) (proxyI.Server, error) {
	return &Server{}, nil
}

func NewRedir(host string) (proxyI.Server, error) {
	return &Server{}, nil
}

func (r *Server) Close() error {
	return nil
}

func (r *Server) UpdateListen(host string) (err error) {
	return nil
}

func (r *Server) SetTCPConn(conn func(string) (net.Conn, error)) {
}
