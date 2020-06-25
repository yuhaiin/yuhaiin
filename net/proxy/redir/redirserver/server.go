package redirserver

import (
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/net/proxy/interfaces"
)

type Server struct {
	listener net.Listener
	closed   bool
}

func NewRedir(host string) (interfaces.Server, error) {
	if host == "" {
		return &Server{}, nil
	}
	s := &Server{}
	return s, s.Redir(host)
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
			go handleRedir(req)
		}
	}()
	return
}
