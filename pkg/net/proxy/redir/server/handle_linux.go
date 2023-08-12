package server

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/nfutil"
)

func handle(req net.Conn, f netapi.Handler) error {
	_ = req.(*net.TCPConn).SetKeepAlive(true)
	target, err := nfutil.GetOrigDst(req.(*net.TCPConn), false)
	if err != nil {
		return err
	}
	f.Stream(context.TODO(), &netapi.StreamMeta{
		Source:      netapi.EmptyAddr,
		Destination: netapi.EmptyAddr,
		Src:         req,
		Address:     netapi.ParseTCPAddress(target),
	})
	return nil
}
