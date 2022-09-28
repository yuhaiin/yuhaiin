//go:build !windows
// +build !windows

package server

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/server"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func RedirHandle(dialer proxy.Proxy) func(net.Conn) {
	return func(conn net.Conn) {
		err := handle(conn, dialer)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
}

func NewServer(o *config.Opts[*config.ServerProtocol_Redir]) (iserver.Server, error) {
	return server.NewTCPServer(o.Protocol.Redir.Host, RedirHandle(o.Dialer))
}
