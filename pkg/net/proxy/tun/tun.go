package tun

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	tun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func init() {
	listener.RegisterProtocol2(NewTun)
}

func NewTun(o *listener.Inbound_Tun) func(listener.InboundI) (s netapi.ProtocolServer, err error) {
	if o.Tun.Driver == listener.Tun_system_gvisor {
		return tun2socket.New(o)
	} else {
		return tun.New(o)
	}
}
