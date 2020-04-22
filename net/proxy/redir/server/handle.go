//+build !windows,!darwin

package server

import (
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/nfutil"
)

func handleRedir(req net.Conn) error {
	defer req.Close()
	_ = req.(*net.TCPConn).SetKeepAlive(true)
	target, err := nfutil.GetOrigDst(req.(*net.TCPConn), false)
	if err != nil {
		return err
	}

	var rsp net.Conn
	if ForwardFunc != nil {
		rsp, err = ForwardFunc(target.String())
	} else {
		rsp, err = net.DialTimeout("tcp", target.String(), 10*time.Second)
	}
	defer rsp.Close()
	common.Forward(req, rsp)
	return nil
}
