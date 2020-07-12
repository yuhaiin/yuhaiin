//+build !windows,!darwin

package redirserver

import (
	"net"

	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/nfutil"
)

func handle(req net.Conn, dst func(string) (net.Conn, error)) error {
	defer req.Close()
	_ = req.(*net.TCPConn).SetKeepAlive(true)
	target, err := nfutil.GetOrigDst(req.(*net.TCPConn), false)
	if err != nil {
		return err
	}

	rsp, err := dst(target.String())
	if err != nil {
		return err
	}
	defer rsp.Close()
	common.Forward(req, rsp)
	return nil
}
