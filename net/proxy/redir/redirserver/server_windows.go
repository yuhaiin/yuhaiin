//+build windows

package redirserver

import (
	"net"

	"github.com/Asutorufa/yuhaiin/net/proxy/proxy"
)

type Server struct {
}

type Option struct {
	TcpConn func(string) (net.Conn, error)
}

func New(host string, modeOption ...func(*Option)) (proxy.Server, error) {
	return &Server{}, nil
}

func NewRedir(host string) (proxy.Server, error) {
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
