package server

import (
	rs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/server"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func init() {
	protoconfig.RegisterProtocol(rs.NewServer)
}
