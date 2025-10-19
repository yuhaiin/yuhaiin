package server

import (
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

type redir struct {
	netapi.EmptyInterface
	lis     net.Listener
	handler netapi.Handler
}

func (r *redir) Close() error {
	return r.lis.Close()
}

func (r *redir) AcceptPacket() (*netapi.Packet, error) {
	return nil, io.EOF
}

func NewServer(o *config.Redir) func(netapi.Listener, netapi.Handler) (netapi.Accepter, error) {
	return func(ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
		t := &redir{
			lis:     ii,
			handler: handler,
		}

		go func() {
			for {
				conn, err := ii.Accept()
				if err != nil {
					log.Error("redir accept failed", "err", err)
					break
				}

				go func() {
					if err := t.handle(conn); err != nil {
						log.Error("redir handle failed", "err", err)
					}
				}()
			}
		}()

		return t, nil
	}
}
