//go:build !android
// +build !android

package inbound

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	cl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func init() {
	cl.RegisterProtocol(func(O *cl.Protocol_Redir) (netapi.ProtocolServer, error) {
		return cl.Listen(&cl.Inbound{
			Network: &cl.Inbound_Tcpudp{
				Tcpudp: &cl.Tcpudp{
					Host: O.Redir.Host,
				},
			},
			Protocol: &cl.Inbound_Redir{
				Redir: O.Redir,
			},
		})
	})
	cl.RegisterProtocol(func(o *cl.Protocol_Tproxy) (netapi.ProtocolServer, error) {
		return cl.Listen(&cl.Inbound{
			Network: &cl.Inbound_Tcpudp{
				Tcpudp: &cl.Tcpudp{
					Host: o.Tproxy.Host,
				},
			},
			Protocol: &cl.Inbound_Tproxy{
				Tproxy: o.Tproxy,
			},
		})
	})
}
