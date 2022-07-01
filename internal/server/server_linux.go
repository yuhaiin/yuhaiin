package server

import (
	"errors"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	rs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/server"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func init() {
	protoconfig.RegisterProtocol(func(t *protoconfig.ServerProtocol_Redir, opts ...func(*protoconfig.Opts)) (iserver.Server, error) {
		if !t.Redir.Enabled {
			return nil, fmt.Errorf("redir server is disabled")
		}
		x := &protoconfig.Opts{Dialer: proxy.NewErrProxy(errors.New("not implemented"))}
		for _, o := range opts {
			o(x)
		}

		return rs.NewServer(t.Redir.GetHost(), x.Dialer)
	})
}
