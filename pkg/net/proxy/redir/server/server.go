package server

import (
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

type redir struct {
	lis net.Listener
	*netapi.ChannelServer
}

func (r *redir) Close() error {
	r.ChannelServer.Close()
	return r.lis.Close()
}

func (r *redir) AcceptPacket() (*netapi.Packet, error) {
	return nil, io.EOF
}

func NewServer(o *listener.Inbound_Redir) func(netapi.Listener) (netapi.Accepter, error) {
	return func(ii netapi.Listener) (netapi.Accepter, error) {
		channel := netapi.NewChannelServer()
		lis, err := ii.Stream(channel.Context())
		if err != nil {
			channel.Close()
			return nil, err
		}

		t := &redir{
			lis:           lis,
			ChannelServer: channel,
		}

		go func() {
			for {
				conn, err := lis.Accept()
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
