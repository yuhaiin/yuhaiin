package server

import (
	"net"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/pfutil"
)

func handle(req net.Conn, f proxy.Handler) error {
	_ = req.(*net.TCPConn).SetKeepAlive(true)
	target, err := pfutil.NatLookup(req.(*net.TCPConn))
	if err != nil {
		return err
	}

	f.Stream(context.TODO(), &proxy.StreamMeta{
		Source:      proxy.EmptyAddr,
		Destination: proxy.EmptyAddr,
		Src:         req,
		Address:     proxy.ParseTCPAddress(target),
	})
	return nil
}
