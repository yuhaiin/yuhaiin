package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (t *tunServer) udpForwarder() *udp.Forwarder {
	handle := func(ctx context.Context, srcpconn net.PacketConn, dst netapi.Address) error {
		buf := pool.GetBytesV2(t.mtu)

		for {
			srcpconn.SetReadDeadline(time.Now().Add(time.Minute))
			n, src, err := srcpconn.ReadFrom(buf.Bytes())
			if err != nil {
				if ne, ok := err.(net.Error); (ok && ne.Timeout()) || err == io.EOF {
					return nil /* ignore I/O timeout & EOF */
				}

				return err
			}

			buf.ResetSize(0, n)

			select {
			case <-t.ctx.Done():
				return t.ctx.Err()

			case t.udpChannel <- &netapi.Packet{

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
					return srcpconn.WriteTo(b, src)
				},
			}:
			}
		}
	}

	return udp.NewForwarder(t.stack, func(fr *udp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := fr.CreateEndpoint(&wq)
		if err != nil {
			log.Error("create endpoint failed:", "err", err)
			return
		}

		local := gonet.NewUDPConn(&wq, ep)

		go func(local net.PacketConn, id stack.TransportEndpointID) {
			defer local.Close()

			ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
			defer cancel()

			dst := netapi.ParseAddressPort(statistic.Type_udp, id.LocalAddress.String(), netapi.ParsePort(id.LocalPort))

			if err := handle(ctx, local, dst); err != nil && !errors.Is(err, os.ErrClosed) {
				log.Error("handle udp request failed", "err", err)
			}

		}(local, fr.ID())
	})
}
