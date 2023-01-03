//go:build !android
// +build !android

package server

import (
	rs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/server"
	cl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func init() {
	cl.RegisterProtocol(rs.NewServer)
}
