package tun

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	tun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

type tunServer struct {
	s        server.Server
	natTable *nat.Table
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
	natTable := nat.NewTable(o.Dialer)

	if o.Protocol.Tun.Driver == listener.Tun_system_gvisor {
		s, err = tun2socket.New(natTable, o)
	} else {
		s, err = tun.NewTun(natTable, o)
	}
	if err != nil {
		return nil, fmt.Errorf("open tun device failed: %w", err)
	}

	return &tunServer{s, natTable}, nil
}
