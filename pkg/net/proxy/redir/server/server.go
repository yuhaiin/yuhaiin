package server

import (
	"net"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tproxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func NewServer(o *listener.Opts[*listener.Protocol_Redir]) (proxy.Server, error) {
	return tproxy.NewTCPServer(o.Protocol.Redir.Host, func(c net.Conn) { handle(c, o.Handler) })
}
