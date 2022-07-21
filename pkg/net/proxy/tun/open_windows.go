package tun

import (
	"fmt"
	"log"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	buffer "gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	WintunTunnelType          = "WireGuard"
	WintunStaticRequestedGUID *windows.GUID
)

func open(name string, _ config.TunEndpointDriver, mtu int) (_ stack.LinkEndpoint, err error) {
	if !strings.HasPrefix(name, "tun://") {
		return nil, fmt.Errorf("invalid tun name: %s", name)
	}

	adapter, err := wintun.CreateAdapter(name[6:], WintunTunnelType, WintunStaticRequestedGUID)
	// adapter, err := wintun.OpenAdapter(name)
	if err != nil {
		return nil, fmt.Errorf("open adapter failed: %w", err)
	}

	session, err := adapter.StartSession(0x800000) // Ring capacity, 8 MiB
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("start session failed: %w", err)
	}

	e := NewEndpoint(&winWriter{session}, uint32(mtu), "")
	e.SetInbound(&winInbound{e, session, adapter})
	return e, nil
}

var _ writer = (*winWriter)(nil)

type winWriter struct{ session wintun.Session }

func (w *winWriter) Write(b []byte) tcpip.Error {
	l := len(b)
	packet, err := w.session.AllocateSendPacket(l)
	if err == nil {
		copy(packet, b)
		w.session.SendPacket(packet)
		return nil
	}

	log.Println("allocate send packet failed: ", err)

	switch err {
	case windows.ERROR_HANDLE_EOF:
		return &tcpip.ErrAborted{}
	case windows.ERROR_BUFFER_OVERFLOW:
		return nil
	}

	return &tcpip.ErrClosedForSend{}
}

// func (w *winWriter) WritePacket(pkt *stack.PacketBuffer) tcpip.Error {
// 	v := buffer.NewVectorisedView(pkt.Size(), pkt.Views())
// 	return w.Write(v.ToView())
// }

func (w *winWriter) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	// for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
	// 	if err := w.WritePacket(pkt); err != nil {
	// 		return 0, err
	// 	}
	// }
	for _, pkt := range pkts.AsSlice() {
		if err := w.Write(pkt.Data().AsRange().ToSlice()); err != nil {
			return 0, err
		}
	}

	return pkts.Len(), nil
}

var _ inbound = (*winInbound)(nil)

type winInbound struct {
	e       stack.InjectableLinkEndpoint
	session wintun.Session
	adapter *wintun.Adapter
}

func (w *winInbound) stop() {
	w.session.End()
	w.adapter.Close()
}

func (w *winInbound) dispatch() (bool, tcpip.Error) {
	packet, err := w.session.ReceivePacket()
	if err != nil {
		log.Println("receive packet failed: ", err)
		return false, &tcpip.ErrAborted{}
	}
	defer w.session.ReleaseReceivePacket(packet)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	defer pkt.DecRef()

	var p tcpip.NetworkProtocolNumber

	switch header.IPVersion(packet) {
	case header.IPv4Version:
		p = header.IPv4ProtocolNumber
	case header.IPv6Version:
		p = header.IPv6ProtocolNumber
	default:
		return true, nil
	}

	w.e.InjectInbound(p, pkt)
	return true, nil
}
