package server

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tproxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func RedirHandle(dialer proxy.Proxy) func(net.Conn) {
	return func(conn net.Conn) {
		err := handle(conn, dialer)
		if err != nil {
			log.Error("redir handle failed", "err", err)
			return
		}
	}
}

func NewServer(o *listener.Opts[*listener.Protocol_Redir]) (iserver.Server, error) {
	return tproxy.NewTCPServer(o.Protocol.Redir.Host, RedirHandle(o.Dialer))
}
