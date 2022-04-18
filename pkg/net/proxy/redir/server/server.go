//go:build !windows
// +build !windows

package server

import (
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

func RedirHandle(dialer proxy.Proxy) func(net.Conn) {
	return func(conn net.Conn) {
		err := handle(conn, dialer)
		if err != nil {
			log.Println(err)
			return
		}
	}
}

func NewServer(host string, dialer proxy.Proxy) (proxy.Server, error) {
	return proxy.NewTCPServer(host, RedirHandle(dialer))
}
