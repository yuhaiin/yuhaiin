package server

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tproxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func NewServer(o *listener.Opts[*listener.Protocol_Redir]) (netapi.Server, error) {
	return tproxy.NewTCPServer(o.Protocol.Redir.Host, func(c net.Conn) {
		if err := handle(c, o.Handler); err != nil {
			log.Error("redir handle failed", "err", err)
		}
	})
}
