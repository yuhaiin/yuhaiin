package server

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/nfutil"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

func handle(req net.Conn, f proxy.Proxy) error {
	defer req.Close()
	_ = req.(*net.TCPConn).SetKeepAlive(true)
	target, err := nfutil.GetOrigDst(req.(*net.TCPConn), false)
	if err != nil {
		return err
	}

	rsp, err := f.Conn(context.TODO(), proxy.ParseTCPAddress(target))
	if err != nil {
		return err
	}

	if rsp, ok := rsp.(*net.TCPConn); ok {
		_ = rsp.SetKeepAlive(true)
	}

	defer rsp.Close()
	relay.Relay(req, rsp)
	return nil
}
