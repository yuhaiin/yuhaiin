package tproxy

import (
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	cl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

type Tproxy struct {
	lis netapi.Listener

	lisAddr netip.AddrPort

	*netapi.ChannelServer
}

func init() {
	listener.RegisterProtocol(NewTproxy)
}

func NewTproxy(opt *cl.Inbound_Tproxy) func(netapi.Listener) (netapi.Accepter, error) {
	return func(ii netapi.Listener) (netapi.Accepter, error) {
		t := &Tproxy{
			ChannelServer: netapi.NewChannelServer(),
			lis:           ii,
		}

		if err := t.newTCP(); err != nil {
			return nil, err
		}

		if err := t.newUDP(); err != nil {
			t.Close()
			return nil, err
		}

		return t, nil
	}
}

func (t *Tproxy) Close() error {
	t.ChannelServer.Close()
	return t.lis.Close()
}
