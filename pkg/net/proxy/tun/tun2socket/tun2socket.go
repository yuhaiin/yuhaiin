package tun2socket

import (
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
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

	o.Device = device

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

	for {
		conn, err := h.nat.TCP.Accept()
		if err != nil {
			break
		}

		go h.handleTCP(conn)
	}
}

func (h *Tun2socket) handleTCP(conn *Conn) {
	// lAddrPort := conn.LocalAddr().(*net.TCPAddr).AddrPort()  // source
	rAddrPort := conn.RemoteAddr().(*net.TCPAddr) // dst

	if rAddrPort.IP.IsLoopback() && rAddrPort.Port == int(h.nat.gatewayPort) {
		conn.Close()
		return
	}

	addr, _ := netapi.ParseSysAddr(rAddrPort)
	h.handler.HandleStream(&netapi.StreamMeta{
		Source:      conn.LocalAddr(),
		Destination: conn.RemoteAddr(),
		Src:         conn,
		Address:     addr,
		DnsRequest:  h.nat.IsDNSRequest(uint16(rAddrPort.Port), conn.tuple.DestinationAddr),
	})
}
