package server

import (
	"bytes"
	"context"
	"log/slog"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

func (s *Socks5) startUDPServer() error {
	packet, err := s.lis.Packet(s.ctx)
	if err != nil {
		return err
	}

	go func() {
		defer packet.Close()
		StartUDPServer(s.ctx, packet, s.udpChannel)
	}()

	return nil
}

func StartUDPServer(ctx context.Context, packet net.PacketConn, channel chan *netapi.Packet) {
	for {
		buf := pool.GetBytesV2(nat.MaxSegmentSize)

		n, src, err := packet.ReadFrom(buf.Bytes())
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

		select {
		case <-ctx.Done():
			return
		case channel <- &netapi.Packet{
			Src:     src,
			Dst:     addr.Address(statistic.Type_udp),
			Payload: buf,
			WriteBack: func(b []byte, source net.Addr) (int, error) {
				sourceAddr, err := netapi.ParseSysAddr(source)
				if err != nil {
					return 0, err
				}
				b = bytes.Join([][]byte{{0, 0, 0}, s5c.ParseAddr(sourceAddr), b}, nil)

				return packet.WriteTo(b, src)
			},
		}:
		}
	}
}
