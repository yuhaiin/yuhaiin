package server

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func NewServer(o *listener.Opts[*listener.Protocol_Redir]) (netapi.Server, error) {
	lis, err := dialer.ListenContext(context.TODO(), "tcp", o.Protocol.Redir.Host)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Error("redir accept failed", "err", err)
				break
			}

			go func() {
				if err := handle(conn, o.Handler); err != nil {
					log.Error("redir handle failed", "err", err)
				}
			}()
		}
	}()

	return lis, nil
}
