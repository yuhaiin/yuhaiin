package socks5server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type udpServer struct {
	net.PacketConn
	natTable *nat.Table
}

func newUDPServer(f proxy.Proxy) (net.PacketConn, error) {
	l, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen udp failed: %v", err)
	}

	u := &udpServer{PacketConn: l, natTable: nat.NewTable(f)}

	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		go u.handle()
	}

	return u, nil
}

func (u *udpServer) handle() {
	buf := pool.GetBytes(nat.MaxSegmentSize)
	defer pool.PutBytes(buf)

	for {
		n, laddr, err := u.PacketConn.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Errorln("read from local failed:", err)
			}
			return
		}

		addr, err := s5c.ResolveAddr(bytes.NewReader(buf[3:n]))
		if err != nil {
			log.Errorf("resolve addr failed: %v", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second*15)
		defer cancel()

		dst := addr.Address(statistic.Type_udp)
		dst.WithContext(ctx)

		err = u.natTable.Write(
			&nat.Packet{
				SourceAddress:      laddr,
				DestinationAddress: dst,
				Payload:            buf[3+len(addr) : n],
				WriteBack: func(b []byte, source net.Addr) (int, error) {
					sourceAddr, err := proxy.ParseSysAddr(source)
					if err != nil {
						return 0, err
					}
					b = bytes.Join([][]byte{{0, 0, 0}, s5c.ParseAddr(sourceAddr), b}, nil)

					return u.PacketConn.WriteTo(b, laddr)
				},
			},
		)
		if err != nil && !errors.Is(err, os.ErrClosed) {
			log.Errorln("write to nat table failed:", err)
		}
	}
}

func (u *udpServer) Close() error {
	u.natTable.Close()
	return u.PacketConn.Close()
}
