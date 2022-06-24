//go:build !android && !windows
// +build !android,!windows

package server

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func init() {
	protoconfig.RegisterProtocol(func(t *protoconfig.ServerProtocol_Socks5, dialer proxy.Proxy) (iserver.Server, error) {
		return ss.NewServer(t.Socks5.Host, t.Socks5.Username, t.Socks5.Password, dialer)
	})
}
