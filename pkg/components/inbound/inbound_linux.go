//go:build !android
// +build !android

package inbound

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/server"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tproxy"
	cl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func init() {
	cl.RegisterProtocol(func(O *cl.Protocol_Redir) (netapi.ProtocolServer, error) {
		return cl.Listen(&cl.Inbound{
			Network: &cl.Inbound_Empty{Empty: &cl.Empty{}},
			Protocol: &cl.Inbound_Redir{
				Redir: O.Redir,
			},
		})
	})
	cl.RegisterProtocol(func(o *cl.Protocol_Tproxy) (netapi.ProtocolServer, error) {
		return cl.Listen(&cl.Inbound{
			Network: &cl.Inbound_Empty{Empty: &cl.Empty{}},
			Protocol: &cl.Inbound_Tproxy{
				Tproxy: o.Tproxy,
			},
		})
	})
}
