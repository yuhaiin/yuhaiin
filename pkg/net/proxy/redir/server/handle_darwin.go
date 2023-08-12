package server

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/pfutil"
)

func handle(req net.Conn, f netapi.Handler) error {
	_ = req.(*net.TCPConn).SetKeepAlive(true)
	target, err := pfutil.NatLookup(req.(*net.TCPConn))
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
