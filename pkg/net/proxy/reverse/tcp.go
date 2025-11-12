package reverse

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterProtocol(NewTCPServer)
}

func NewTCPServer(o *config.ReverseTcp, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	target, err := netapi.ParseAddress("tcp", o.GetHost())
	if err != nil {
		return nil, err
	}

	go func() {
		ii := netapi.NewErrCountListener(ii, 10)
		for {
			conn, err := ii.Accept()
			if err != nil {
				log.Error("reverse tcp accept failed", "err", err)
				break
			}

			go func() {
				handler.HandleStream(&netapi.StreamMeta{
					Destination: target,
					Src:         conn,
					Inbound:     ii.Addr(),
					Address:     target,
					Source:      conn.RemoteAddr(),
				})
			}()
		}
	}()

	return &accepter{Listener: ii}, nil
}
