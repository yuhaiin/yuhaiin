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
	*netapi.ChannelProtocolServer
}

func (r *redir) Close() error {
	r.ChannelProtocolServer.Close()
	return r.lis.Close()
}

func (r *redir) AcceptPacket() (*netapi.Packet, error) {
	return nil, io.EOF
}

func NewServer(o *listener.Inbound_Redir) func(netapi.Listener) (netapi.ProtocolServer, error) {
	return func(ii netapi.Listener) (netapi.ProtocolServer, error) {
		channel := netapi.NewChannelProtocolServer()
		lis, err := ii.Stream(channel.Context())
		if err != nil {
			channel.Close()
			return nil, err
		}

		t := &redir{
			lis:                   lis,
			ChannelProtocolServer: channel,
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
