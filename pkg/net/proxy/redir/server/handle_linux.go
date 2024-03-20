package server

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/nfutil"
)

func (r *redir) handle(req net.Conn) error {
	target, err := nfutil.GetOrigDst(req.(*net.TCPConn), false)
	if err != nil {
		return err
	}

	return r.SendStream(&netapi.StreamMeta{
		Inbound:     r.lis.Addr(),
		Source:      req.RemoteAddr(),
		Destination: target,
		Src:         req,
		Address:     netapi.ParseTCPAddress(target),
	})
}
