package tun

import (
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (t *tunServer) udpForwarder() *udp.Forwarder {
	return udp.NewForwarder(t.stack, func(fr *udp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := fr.CreateEndpoint(&wq)
		if err != nil {
			log.Error("create endpoint failed:", "err", err)
			return
		}

		local := gonet.NewUDPConn(&wq, ep)

		go func(local *gonet.UDPConn, id stack.TransportEndpointID) {
			defer local.Close()

			addr, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
			if !ok {
				return
			}

			dst := netapi.ParseAddrPort(statistic.Type_udp, netip.AddrPortFrom(addr, id.LocalPort))

			for {
				buf := pool.GetBytesBuffer(t.mtu)

				_ = local.SetReadDeadline(time.Now().Add(nat.IdleTImeout))
				n, src, err := local.ReadFrom(buf.Bytes())
				if err != nil {
					if ne, ok := err.(net.Error); (ok && ne.Timeout()) || err == io.EOF {
						return /* ignore I/O timeout & EOF */
					}

					log.Error("read udp failed:", "err", err)
					return
				}

				buf.ResetSize(0, n)

				err = t.SendPacket(&netapi.Packet{
					Src:     src,
					Dst:     dst,
					Payload: buf,
					WriteBack: func(b []byte, addr net.Addr) (int, error) {
						from, err := netapi.ParseSysAddr(addr)
						if err != nil {
							return 0, err
						}

						// Symmetric NAT
						// gVisor udp.NewForwarder only support Symmetric NAT,
						// can't set source in udp header
						// TODO: rewrite HandlePacket() to support full cone NAT
						if from.String() != dst.String() {
							return 0, nil
						}

						n, err := local.WriteTo(b, src)
						if err != nil {
							return n, err
						}

						_ = local.SetReadDeadline(time.Now().Add(nat.IdleTImeout))
						return n, nil
					},
				})
				if err != nil {
					return
				}
			}

		}(local, fr.ID())
	})
}
