//+build !windows

package redirserver

import (
	"errors"
	"log"
	"net"

	proxyI "github.com/Asutorufa/yuhaiin/net/proxy/interface"
)

type Server struct {
	proxyI.Server
	listener net.Listener
	closed   bool
	tcpConn  func(string) (net.Conn, error)
}

type Option struct {
	TcpConn func(string) (net.Conn, error)
}

func New(host string, modeOption ...func(*Option)) (proxyI.Server, error) {
	if host == "" {
		return nil, errors.New("host empty")
	}
	s := &Server{}
	o := &Option{
		TcpConn: func(s string) (net.Conn, error) {
			return net.Dial("tcp", s)
		},
	}
	for index := range modeOption {
		if modeOption[index] == nil {
			continue
		}
		modeOption[index](o)
	}

	s.tcpConn = o.TcpConn
	err := s.Redir(host)
	return s, err
}

func (r *Server) Close() error {
	r.closed = true
	return r.listener.Close()
}

func (r *Server) UpdateListen(host string) (err error) {
	if r.closed {
		if host == "" {
			return nil
		}
		r.closed = false
		return r.Redir(host)
	}

	if host == "" {
		return r.Close()
	}

	if r.listener.Addr().String() == host {
		return nil
	}
	if err = r.listener.Close(); err != nil {
		log.Println(err)
		return err
	}
	r.listener, err = net.Listen("tcp", host)
	return
}

func (r *Server) SetTCPConn(conn func(string) (net.Conn, error)) {
	if conn == nil {
		return
	}
	r.tcpConn = conn
}

func (r *Server) GetHost() string {
	return r.listener.Addr().String()
}

func (r *Server) Redir(host string) (err error) {
	if r.listener, err = net.Listen("tcp", host); err != nil {
		return err
	}
	go func() {
		for {
			req, err := r.listener.Accept()
			if err != nil {
				if r.closed {
					break
				}
				//log.Print(err)
				continue
			}
			go r.handleRedir(req)
		}
	}()
	return
}

func RedirHandle() func(net.Conn, func(string) (net.Conn, error)) {
	return func(conn net.Conn, f func(string) (net.Conn, error)) {
		err := handle(conn, f)
		if err != nil {
			log.Println(err)
			return
		}
	}
}
