package inbound

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func newReverseTCPServer(target string, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	destination, err := netapi.ParseAddress("tcp", target)
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
					Destination: destination,
					Src:         conn,
					Inbound:     ii.Addr(),
					Address:     destination,
					Source:      conn.RemoteAddr(),
				})
			}()
		}
	}()

	return noopAccepter{Listener: ii}, nil
}
