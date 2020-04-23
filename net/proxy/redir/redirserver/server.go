package redirserver

import (
	"log"
	"net"
)

type Server struct {
	listener net.Listener
}

func NewRedir(host, port string) (s *Server, err error) {
	s = &Server{}
	if s.listener, err = net.Listen("tcp", net.JoinHostPort(host, port)); err != nil {
		return nil, err
	}

	return s, nil
}

func (r *Server) Close() error {
	return r.listener.Close()
}

func (r *Server) UpdateListen(host, port string) (err error) {
	if r.listener.Addr().String() == net.JoinHostPort(host, port) {
		return nil
	}
	if err = r.listener.Close(); err != nil {
		return err
	}
	r.listener, err = net.Listen("tcp", net.JoinHostPort(host, port))
	return
}

func (r *Server) GetHost() string {
	return r.listener.Addr().String()
}

func (r *Server) Redir() (err error) {
	for {
		req, err := r.listener.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go handleRedir(req)
	}
}
