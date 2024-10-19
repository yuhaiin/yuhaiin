package reverse

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func init() {
	listener.RegisterProtocol(NewTCPServer)
}

func NewTCPServer(o *listener.Inbound_ReverseTcp) func(netapi.Listener, netapi.Handler) (netapi.Accepter, error) {
	target, err := netapi.ParseAddress("tcp", o.ReverseTcp.Host)
	if err != nil {
		return func(l netapi.Listener, h netapi.Handler) (netapi.Accepter, error) {
			return nil, err
		}
	}

	return func(ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
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
}
