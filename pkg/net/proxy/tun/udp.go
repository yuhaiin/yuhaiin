package tun

import (
	"io"
	"log"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func udpForwarder(s *stack.Stack, opt *TunOpt) *udp.Forwarder {
	return udp.NewForwarder(s, func(fr *udp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := fr.CreateEndpoint(&wq)
		if err != nil {
			log.Println("create endpoint failed:", err)
			return
		}

		local := gonet.NewUDPConn(s, &wq, ep)

		go func(local net.PacketConn, id stack.TransportEndpointID) {
			defer local.Close()

			if isdns(opt, id) {
				if err := opt.DNS.HandleUDP(local); err != nil {
					log.Printf("dns handle udp failed: %v\n", err)
				}
				return
			}

			addr := proxy.ParseAddressSplit("udp", id.LocalAddress.String(), id.LocalPort)
			if opt.SkipMulticast && addr.Type() == proxy.IP {
				if ip, _ := addr.IP(); !ip.IsGlobalUnicast() {
					buf := utils.GetBytes(utils.DefaultSize)
					defer utils.PutBytes(buf)

					for {
						local.SetReadDeadline(time.Now().Add(60 * time.Second))
						if _, _, err := local.ReadFrom(buf); err != nil {
							return
						}
					}
				}
			}
			addMessage(addr, id, opt)

			conn, er := opt.Dialer.PacketConn(addr)
			if er != nil {
				log.Printf("[UDP] dial %s error: %v\n", addr, er)
				return
			}
			defer conn.Close()

			uaddr, err := addr.UDPAddr()
			if err != nil {
				log.Printf("[UDP] parse %s error: %v\n", addr, err)
				return
			}
			go copyPacketBuffer(conn, local, uaddr, 60*time.Second)
			copyPacketBuffer(local, conn, nil, 60*time.Second)
		}(local, fr.ID())
	})
}

var MaxSegmentSize = (1 << 16) - 1

func copyPacketBuffer(dst net.PacketConn, src net.PacketConn, to net.Addr, timeout time.Duration) error {
	buf := utils.GetBytes(MaxSegmentSize)
	defer utils.PutBytes(buf)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, _, err := src.ReadFrom(buf)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil /* ignore I/O timeout */
		} else if err == io.EOF {
			return nil /* ignore EOF */
		} else if err != nil {
			return err
		}

		if _, err = dst.WriteTo(buf[:n], to); err != nil {
			return err
		}
		dst.SetReadDeadline(time.Now().Add(timeout))
	}
}
