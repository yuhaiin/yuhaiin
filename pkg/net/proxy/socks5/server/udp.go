package server

import (
	"bytes"
	"context"
	"errors"
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

		buf := pool.GetBytes(nat.MaxSegmentSize)
		defer pool.PutBytes(buf)

		for {
			n, src, err := u.PacketConn.ReadFrom(buf)
			if err != nil {
				log.Error("read udp request failed, stop socks5 server", slog.Any("err", err))
				return
			}

			if err := u.handle(buf[:n], src); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Error("handle udp request failed", "err", err)
			}
		}
	}()

	return nil
}

func (u *udpServer) handle(buf []byte, src net.Addr) error {
	addr, err := s5c.ResolveAddr(bytes.NewReader(buf[3:]))
	if err != nil {
		return fmt.Errorf("resolve addr failed: %w", err)
	}

	u.handler.Packet(
		context.TODO(),
		&netapi.Packet{
			Src:     src,
			Dst:     addr.Address(statistic.Type_udp),
			Payload: buf[3+len(addr):],
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
	return nil
}
