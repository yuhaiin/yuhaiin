//go:build !android
// +build !android

package inbound

import (
	rs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tproxy"
	cl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func init() {
	cl.RegisterProtocol(rs.NewServer)
	cl.RegisterProtocol(tproxy.NewTproxy)
}
