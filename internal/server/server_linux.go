//go:build !android && !windows
// +build !android,!windows

package server

import (
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func init() {
	protoconfig.RegisterProtocol(func(t *protoconfig.ServerProtocol_Socks5, opts ...func(*protoconfig.Opts)) (iserver.Server, error) {
		x := &protoconfig.Opts{Dialer: proxy.NewErrProxy(errors.New("not implemented"))}
		for _, o := range opts {
			o(x)
		}
		return ss.NewServer(t.Socks5.Host, t.Socks5.Username, t.Socks5.Password, x.Dialer)
	})
}
