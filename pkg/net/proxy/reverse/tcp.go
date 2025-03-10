package reverse

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterProtocol(NewTCPServer)
}

func NewTCPServer(o *listener.ReverseTcp, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	target, err := netapi.ParseAddress("tcp", o.GetHost())
	if err != nil {
		return nil, err
	}

	lis, err := ii.Stream(context.TODO())
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Error("reverse tcp accept failed", "err", err)
				break
			}

			go func() {
				handler.HandleStream(&netapi.StreamMeta{
					Destination: target,
					Src:         conn,
					Inbound:     lis.Addr(),
					Address:     target,
					Source:      conn.RemoteAddr(),
				})
			}()
		}
	}()

	return lis, nil
}
