package tun

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	socks5server "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	tun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

type tunServer struct {
	s        server.Server
	natTable *socks5server.NatTable
}

func (t *tunServer) Close() error {
	if t.s != nil {
		t.s.Close()
	}

	if t.natTable != nil {
		t.natTable.Close()
	}

	return nil
}

func NewTun(o *listener.Opts[*listener.Protocol_Tun]) (s server.Server, err error) {
	natTable := socks5server.NewNatTable(o.Dialer)

	if o.Protocol.Tun.Driver == listener.Tun_tun2socket {
		s, err = tun2socket.New(natTable, o)
	} else {
		s, err = tun.NewTun(natTable, o)
	}
	if err != nil {
		return nil, fmt.Errorf("open tun device failed: %w", err)
	}

	return &tunServer{s, natTable}, nil
}
