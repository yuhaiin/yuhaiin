package redirserver

import (
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/pfutil"
)

func handleRedir(req net.Conn) error {
	defer req.Close()
	_ = req.(*net.TCPConn).SetKeepAlive(true)
	target, err := pfutil.NatLookup(req.(*net.TCPConn))
	if err != nil {
		return err
	}

	var rsp net.Conn
	if common.ForwardTarget != nil {
		rsp, err = common.ForwardTarget(target.String())
	} else {
		rsp, err = net.DialTimeout("tcp", target.String(), 10*time.Second)
	}
	defer rsp.Close()
	common.Forward(req, rsp)
	return nil
}
