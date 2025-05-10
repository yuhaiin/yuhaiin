package tun2socket

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
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
