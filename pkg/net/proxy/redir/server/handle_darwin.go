package server

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/pfutil"
)

func (r *redir) handle(req net.Conn) error {
	target, err := pfutil.NatLookup(req.(*net.TCPConn))
	if err != nil {
		return err
	}

	r.handler.HandleStream(&netapi.StreamMeta{
		Inbound:     r.lis.Addr(),
		Source:      req.RemoteAddr(),
		Destination: target,
		Src:         req,
		Address:     netapi.ParseIPAddr("tcp", target.IP, uint16(target.Port)),
	})

	return nil
}
