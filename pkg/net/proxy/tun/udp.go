package tun

import (
	"errors"
	"log"
	"net"
	"os"
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
			return
		}

		local := gonet.NewUDPConn(s, &wq, ep)

		go func(local net.PacketConn, id stack.TransportEndpointID) {
			defer local.Close()

			if isDNSReq(opt, id) {
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

			conn, er := opt.Dialer.PacketConn(addr)
			if er != nil {
				return
			}
			defer conn.Close()

			uaddr, err := addr.UDPAddr()
			if err != nil {
				return
			}
			go handleUDPToRemote(local, conn, uaddr)
			handleUDPToLocal(local, conn, uaddr)
		}(local, fr.ID())
	})
}

var MaxSegmentSize = (1 << 16) - 1

func handleUDPToRemote(uc, pc net.PacketConn, remote net.Addr) {
	buf := utils.GetBytes(MaxSegmentSize)
	defer utils.PutBytes(buf)

	for {
		n, _, err := uc.ReadFrom(buf)
		if err != nil {
			return
		}

		if _, err := pc.WriteTo(buf[:n], remote); err != nil {
			log.Printf("[UDP] write to %s error: %v\n", remote, err)
		}
		pc.SetReadDeadline(time.Now().Add(20 * time.Second)) /* reset timeout */
	}
}

func handleUDPToLocal(uc, pc net.PacketConn, remote net.Addr) {
	buf := utils.GetBytes(MaxSegmentSize)
	defer utils.PutBytes(buf)

	for {
		pc.SetReadDeadline(time.Now().Add(20 * time.Second)) /* reset timeout */
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) /* ignore I/O timeout */ {
				log.Printf("[UDP] read error: %v\n", err)
			}
			return
		}

		if _, err := uc.WriteTo(buf[:n], nil); err != nil {
			log.Printf("[UDP] write back from %s error: %v\n", from, err)
			return
		}
	}
}
