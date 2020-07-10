package redirserver

import (
	"net"

	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/pfutil"
)

func (r *Server) handleRedir(req net.Conn) error {
	defer req.Close()
	_ = req.(*net.TCPConn).SetKeepAlive(true)
	target, err := pfutil.NatLookup(req.(*net.TCPConn))
	if err != nil {
		return err
	}

	rsp, err := r.tcpConn(target.String())
	if err != nil {
		return err
	}
	defer rsp.Close()
	common.Forward(req, rsp)
	return nil
}
