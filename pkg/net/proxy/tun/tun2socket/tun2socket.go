package tun2socket

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type Tun2socket struct {
	device io.Closer
	nat    *Nat

	handler netapi.Handler
	Mtu     int32
}

func New(o *device.Opt) (netapi.Accepter, error) {
	device, err := device.OpenWriter(o.Interface, int(o.Tun.GetMtu()))
	if err != nil {
		return nil, fmt.Errorf("open tun device failed: %w", err)
	}

	o.Writer = device

	nat, err := Start(o)
	if err != nil {
		device.Close()
		return nil, err
	}

	handler := &Tun2socket{
		nat:     nat,
		device:  device,
		Mtu:     o.Tun.GetMtu(),
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

func (h *Tun2socket) handleUDP(tuple UDPTuple, buf []byte) {
	h.handler.HandlePacket(&netapi.Packet{
		Src:       netapi.ParseIPAddr("udp", net.IP(tuple.SourceAddr.AsSlice()), tuple.SourcePort),
		Dst:       netapi.ParseIPAddr("udp", net.IP(tuple.DestinationAddr.AsSlice()), tuple.DestinationPort),
		Payload:   pool.Clone(buf),
		WriteBack: &WriteBack{h, tuple},
	})
}

type WriteBack struct {
	*Tun2socket
	tuple UDPTuple
}

func (h *WriteBack) toTuple(addr net.Addr) (UDPTuple, error) {
	address, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return UDPTuple{}, err
	}

	daddr, err := dialer.ResolverIP(context.TODO(), address)
	if err != nil {
		return UDPTuple{}, err
	}

	if h.tuple.SourceAddr.Len() == 16 {
		daddr = daddr.To16()
	}

	return UDPTuple{
		DestinationAddr: tcpip.AddrFromSlice(daddr),
		DestinationPort: uint16(address.Port()),
		SourceAddr:      h.tuple.SourceAddr,
		SourcePort:      h.tuple.SourcePort,
	}, nil
}

func (h *WriteBack) WriteBack(b []byte, addr net.Addr) (int, error) {
	tuple, err := h.toTuple(addr)
	if err != nil {
		return 0, err
	}

	return h.nat.UDP.WriteTo(b, tuple)
}

// func (h *WriteBack) WriteBatch(bufs ...netapi.WriteBatchBuf) error {
// 	batch := make([]Batch, 0, len(bufs))

// 	for _, buf := range bufs {
// 		tuple, err := h.toTuple(buf.Addr)
// 		if err != nil {
// 			log.Error("parse addr failed:", "err", err)
// 			continue
// 		}

// 		batch = append(batch, Batch{
// 			Payload: buf.Payload,
// 			Tuple:   tuple,
// 		})
// 	}

// 	return h.nat.UDP.WriteBatch(batch)
// }
