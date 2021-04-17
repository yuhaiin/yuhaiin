//+build !windows

package redirserver

import (
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

func RedirHandle() func(net.Conn, proxy.Proxy) {
	return func(conn net.Conn, f proxy.Proxy) {
		err := handle(conn, f)
		if err != nil {
			log.Println(err)
			return
		}
	}
}
