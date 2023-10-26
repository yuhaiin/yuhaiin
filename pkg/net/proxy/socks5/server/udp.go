package server

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type udpServer struct {
	net.PacketConn
	handler netapi.Handler
}

func (s *Socks5) newUDPServer(handler netapi.Handler) error {
	l, err := dialer.ListenPacket("udp", s.addr)
	if err != nil {
		return fmt.Errorf("listen udp failed: %w", err)
	}

	u := &udpServer{PacketConn: l, handler: handler}
	s.udpServer = u

	go func() {
		defer s.Close()

		buf := pool.GetBytesV2(nat.MaxSegmentSize)

		for {
			n, src, err := u.PacketConn.ReadFrom(buf.Bytes())
			if err != nil {
				log.Error("read udp request failed, stop socks5 server", slog.Any("err", err))
				return
			}

			addr, err := s5c.ResolveAddr(bytes.NewReader(buf.Bytes()[3:n]))
			if err != nil {
				log.Error("resolve addr failed", "err", err)
				continue
			}

			buf.ResetSize(3+len(addr), n)

			u.handler.Packet(
				context.TODO(),
				&netapi.Packet{
					Src:     src,
					Dst:     addr.Address(statistic.Type_udp),
					Payload: buf,
					WriteBack: func(b []byte, source net.Addr) (int, error) {
						sourceAddr, err := netapi.ParseSysAddr(source)
						if err != nil {
							return 0, err
						}
						b = bytes.Join([][]byte{{0, 0, 0}, s5c.ParseAddr(sourceAddr), b}, nil)

						return u.PacketConn.WriteTo(b, src)
					},
				},
			)

		}
	}()

	return nil
}
