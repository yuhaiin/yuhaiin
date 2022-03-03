//go:build !windows && !darwin
// +build !windows,!darwin

package server

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/nfutil"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

func handle(req net.Conn, f proxy.Proxy) error {
	defer req.Close()
	_ = req.(*net.TCPConn).SetKeepAlive(true)
	target, err := nfutil.GetOrigDst(req.(*net.TCPConn), false)
	if err != nil {
		return err
	}

	rsp, err := f.Conn(target.String())
	if err != nil {
		return err
	}

	if rsp, ok := rsp.(*net.TCPConn); ok {
		_ = rsp.SetKeepAlive(true)
	}

	defer rsp.Close()
	utils.Relay(req, rsp)
	return nil
}
