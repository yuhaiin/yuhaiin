package tun2socket

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	tun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket/nat"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type Tun2socket struct {
	Mtu int32

	device io.Closer
	nat    *nat.Nat

	*netapi.ChannelServer
}

func New(o *tun.Opt) (netapi.Accepter, error) {
	device, err := tun.OpenWriter(o.Interface, int(o.Tun.Mtu))
	if err != nil {
		return nil, fmt.Errorf("open tun device failed: %w", err)
	}

	o.Writer = device

	nat, err := nat.Start(o)
	if err != nil {
		device.Close()
		return nil, err
	}

	handler := &Tun2socket{
		nat:           nat,
		device:        device,
		Mtu:           o.Tun.Mtu,
		ChannelServer: netapi.NewChannelServer(),
	}

	go handler.tcpLoop()
	go handler.udpLoop()

	return handler, nil
}

func (h *Tun2socket) Close() error {
	h.ChannelServer.Close()
	_ = h.nat.TCP.Close()
	_ = h.nat.UDPv2.Close()
	return h.device.Close()
}

func (h *Tun2socket) tcpLoop() {

	defer h.nat.TCP.Close()

	for h.nat.TCP.SetDeadline(time.Time{}) == nil {
		conn, err := h.nat.TCP.Accept()
		if err != nil {
			log.Error("tun2socket tcp accept failed", "err", err)
			continue
		}

		go func() {
			if err = h.handleTCP(conn); err != nil {
				if errors.Is(err, netapi.ErrBlocked) {
					log.Debug(err.Error())
				} else {
					log.Error("handle tcp failed", "err", err)
				}
			}
		}()

	}
}

func (h *Tun2socket) udpLoop() {
	defer h.nat.UDPv2.Close()
	for {
		if err := h.handleUDP(); err != nil {
			if errors.Is(err, netapi.ErrBlocked) {
				log.Debug(err.Error())
			} else {
				log.Error("handle udp failed", "err", err)
			}
			if errors.Is(err, errUDPAccept) {
				return
			}
		}
	}
}

func (h *Tun2socket) handleTCP(conn net.Conn) error {
	// lAddrPort := conn.LocalAddr().(*net.TCPAddr).AddrPort()  // source
	rAddrPort := conn.RemoteAddr().(*net.TCPAddr) // dst

	if rAddrPort.IP.IsLoopback() {
		return nil
	}

	return h.SendStream(&netapi.StreamMeta{
		Source:      conn.LocalAddr(),
		Destination: conn.RemoteAddr(),
		Src:         conn,
		Address:     netapi.ParseTCPAddress(rAddrPort),
	})
}

var errUDPAccept = errors.New("tun2socket udp accept failed")

func (h *Tun2socket) handleUDP() error {
	buf := pool.GetBytesBuffer(h.Mtu)

	n, tuple, err := h.nat.UDPv2.ReadFrom(buf.Bytes())
	if err != nil {
		return fmt.Errorf("%w: %v", errUDPAccept, err)
	}

	buf.Refactor(0, n)

	return h.SendPacket(&netapi.Packet{
		Src: &net.UDPAddr{
			IP:   net.IP(tuple.SourceAddr.AsSlice()),
			Port: int(tuple.SourcePort),
		},
		Dst: netapi.ParseUDPAddr(&net.UDPAddr{
			IP:   net.IP(tuple.DestinationAddr.AsSlice()),
			Port: int(tuple.DestinationPort),
		}),
		Payload: buf,
		WriteBack: func(b []byte, addr net.Addr) (int, error) {
			address, err := netapi.ParseSysAddr(addr)
			if err != nil {
				return 0, err
			}

			daddr, err := address.IP(context.TODO())
			if err != nil {
				return 0, err
			}

			return h.nat.UDPv2.WriteTo(b, nat.Tuple{
				DestinationAddr: tcpip.AddrFromSlice(daddr),
				DestinationPort: address.Port().Port(),
				SourceAddr:      tuple.SourceAddr,
				SourcePort:      tuple.SourcePort,
			})
		},
	})
}
