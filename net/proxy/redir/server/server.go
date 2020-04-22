package server

import (
	"log"
	"net"
)

var (
	ForwardFunc func(host string) (net.Conn, error)
)

func Redir() error {
	listen, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", "1081"))
	if err != nil {
		return err
	}
	for {
		req, err := listen.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go handleRedir(req)
	}
}
