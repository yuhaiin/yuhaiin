//go:build !windows
// +build !windows

package server

import (
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/server"
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

func NewServer(host string, dialer proxy.Proxy) (iserver.Server, error) {
	return server.NewTCPServer(host, RedirHandle(dialer))
}
