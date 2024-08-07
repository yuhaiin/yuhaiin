package tun2socket

import (
	"context"
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
	device io.Closer
	nat    *nat.Nat

	handler netapi.Handler
	Mtu     int32
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
		nat:     nat,
		device:  device,
		Mtu:     o.Tun.Mtu,
		handler: o.Handler,
	}

	nat.UDP.HandlePacket = handler.handleUDP
	go handler.tcpLoop()

	return handler, nil
}

func (h *Tun2socket) Close() error {
	_ = h.nat.TCP.Close()
	_ = h.nat.UDP.Close()
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

		go h.handleTCP(conn)
	}
}

func (h *Tun2socket) handleTCP(conn net.Conn) {
	// lAddrPort := conn.LocalAddr().(*net.TCPAddr).AddrPort()  // source
	rAddrPort := conn.RemoteAddr().(*net.TCPAddr) // dst

	if rAddrPort.IP.IsLoopback() {
		return
	}

	addr, _ := netapi.ParseSysAddr(rAddrPort)
	h.handler.HandleStream(&netapi.StreamMeta{
		Source:      conn.LocalAddr(),
		Destination: conn.RemoteAddr(),
		Src:         conn,
		Address:     addr,
	})
}

func (h *Tun2socket) handleUDP(tuple nat.Tuple, buf []byte) {
	h.handler.HandlePacket(&netapi.Packet{
		Src: netapi.ParseIPAddrPort("udp",
			net.IP(tuple.SourceAddr.AsSlice()), tuple.SourcePort),
		Dst: netapi.ParseIPAddrPort("udp",
			net.IP(tuple.DestinationAddr.AsSlice()), tuple.DestinationPort),
		Payload: pool.Clone(buf),
		WriteBack: func(b []byte, addr net.Addr) (int, error) {
			address, err := netapi.ParseSysAddr(addr)
			if err != nil {
				return 0, err
			}

			daddr, err := netapi.ResolverIP(context.TODO(), address)
			if err != nil {
				return 0, err
			}

			if tuple.SourceAddr.Len() == 16 {
				daddr = daddr.To16()
			}

			return h.nat.UDP.WriteTo(b, nat.Tuple{
				DestinationAddr: tcpip.AddrFromSlice(daddr),
				DestinationPort: uint16(address.Port()),
				SourceAddr:      tuple.SourceAddr,
				SourcePort:      tuple.SourcePort,
			})
		},
	})
}
