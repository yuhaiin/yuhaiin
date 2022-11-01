package tun

import (
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5s "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func udpForwarder(s *stack.Stack, natTable *s5s.UdpNatTable, opt *listener.Opts[*listener.Protocol_Tun]) *udp.Forwarder {
	handle := func(src net.PacketConn, target proxy.Address) error {
		buf := pool.GetBytes(s5s.MaxSegmentSize)
		defer pool.PutBytes(buf)

		for {
			src.SetReadDeadline(time.Now().Add(time.Minute))
			n, addr, err := src.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); (ok && ne.Timeout()) || err == io.EOF {
					return nil /* ignore I/O timeout & EOF */
				}

				return err
			}

			if err = natTable.Write(buf[:n], addr, target, src); err != nil {
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

			if isHandleDNS(opt, id) {
				if err := opt.DNSServer.HandleUDP(local); err != nil {
					log.Errorf("dns handle udp failed: %v\n", err)
				}
				return
			}

			addr := proxy.ParseAddressSplit("udp", id.LocalAddress.String(), proxy.ParsePort(id.LocalPort))
			if opt.Protocol.Tun.SkipMulticast && addr.Type() == proxy.IP {
				if ip, _ := addr.IP(); !ip.IsGlobalUnicast() {
					buf := pool.GetBytes(pool.DefaultSize)
					defer pool.PutBytes(buf)

					for {
						local.SetReadDeadline(time.Now().Add(time.Minute))
						if _, _, err := local.ReadFrom(buf); err != nil {
							return
						}
					}
				}
			}
			addMessage(addr, id, opt)

			if err := handle(local, addr); err != nil {
				log.Errorln("handle udp request failed:", err)
			}

		}(local, fr.ID())
	})
}
