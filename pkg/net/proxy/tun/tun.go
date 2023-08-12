package tun

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	tun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func NewTun(o *listener.Opts[*listener.Protocol_Tun]) (s netapi.Server, err error) {
	if o.Protocol.Tun.Driver == listener.Tun_system_gvisor {
		s, err = tun2socket.New(o)
	} else {
		s, err = tun.New(o)
	}
	if err != nil {
		return nil, fmt.Errorf("open tun device failed: %w", err)
	}

	return s, nil
}
