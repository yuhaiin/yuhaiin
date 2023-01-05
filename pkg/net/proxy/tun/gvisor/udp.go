package tun

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5s "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func udpForwarder(s *stack.Stack, natTable *s5s.NatTable, opt *listener.Opts[*listener.Protocol_Tun]) *udp.Forwarder {
	handle := func(srcpconn net.PacketConn, dst proxy.Address) error {
		buf := pool.GetBytes(s5s.MaxSegmentSize)
		defer pool.PutBytes(buf)

		for {
			srcpconn.SetReadDeadline(time.Now().Add(time.Minute))
			n, src, err := srcpconn.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); (ok && ne.Timeout()) || err == io.EOF {
					return nil /* ignore I/O timeout & EOF */
				}

				return err
			}

			if err = natTable.Write(buf[:n], src, dst, srcpconn.WriteTo); err != nil {
				return err
			}
		}
	}

	return udp.NewForwarder(s, func(fr *udp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := fr.CreateEndpoint(&wq)
		if err != nil {
			log.Errorln("create endpoint failed:", err)
			return
		}

		local := gonet.NewUDPConn(s, &wq, ep)

		go func(local net.PacketConn, id stack.TransportEndpointID) {
			defer local.Close()

			if tun2socket.IsHandleDNS(opt, id.LocalAddress.String(), id.LocalPort) {
				if err := opt.DNSServer.HandleUDP(local); err != nil {
					log.Errorf("dns handle udp failed: %v\n", err)
				}
				return
			}

			dst := proxy.ParseAddressSplit(statistic.Type_udp, id.LocalAddress.String(), proxy.ParsePort(id.LocalPort))
			if opt.Protocol.Tun.SkipMulticast && dst.Type() == proxy.IP {
				if ip, _ := dst.IP(); !ip.IsGlobalUnicast() {
					buf := pool.GetBytes(1024)
					defer pool.PutBytes(buf)

					for {
						local.SetReadDeadline(time.Now().Add(time.Minute))
						if _, _, err := local.ReadFrom(buf); err != nil {
							return
						}
					}
				}
			}

			if err := handle(local, dst); err != nil && !errors.Is(err, os.ErrClosed) {
				log.Errorln("handle udp request failed:", err)
			}

		}(local, fr.ID())
	})
}
