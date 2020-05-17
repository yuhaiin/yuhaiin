//+build !windows,!darwin

package redirserver

import (
	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/nfutil"
	"net"
)

func handleRedir(req net.Conn) error {
	defer req.Close()
	_ = req.(*net.TCPConn).SetKeepAlive(true)
	target, err := nfutil.GetOrigDst(req.(*net.TCPConn), false)
	if err != nil {
		return err
	}

	rsp, err := common.ForwardTarget(target.String())
	if err != nil {
		return err
	}
	defer rsp.Close()
	common.Forward(req, rsp)
	return nil
}
