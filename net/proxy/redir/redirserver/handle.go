//+build !windows,!darwin

package redirserver

import (
	"net"

	"github.com/Asutorufa/yuhaiin/net/proxy/redir/nfutil"
	"github.com/Asutorufa/yuhaiin/net/utils"
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
	switch rsp.(type) {
	case *net.TCPConn:
		_ = rsp.(*net.TCPConn).SetKeepAlive(true)
	}
	defer rsp.Close()
	utils.Forward(req, rsp)
	return nil
}
