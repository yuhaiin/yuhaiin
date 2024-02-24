package tun2socket

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	tun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket/nat"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/goos"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type Tun2socket struct {
	Mtu int32

	device io.Closer
	nat    *nat.Nat

	ctx   context.Context
	close context.CancelFunc

	tcpChannel chan *netapi.StreamMeta
	udpChannel chan *netapi.Packet
}

func New(o *listener.Inbound_Tun) func(netapi.Listener) (netapi.ProtocolServer, error) {
	return func(ii netapi.Listener) (netapi.ProtocolServer, error) {
		gateway, gerr := netip.ParseAddr(o.Tun.Gateway)
		portal, perr := netip.ParseAddr(o.Tun.Portal)
		if gerr != nil || perr != nil {
			return nil, fmt.Errorf("gateway or portal is invalid")
		}

		sc, err := tun.ParseTunScheme(o.Tun.Name)
		if err != nil {
			return nil, err
		}

		device, err := tun.OpenWriter(sc, int(o.Tun.Mtu))
		if err != nil {
			return nil, fmt.Errorf("open tun device failed: %w", err)
		}

		nat, err := nat.Start(device, sc, gateway, portal, o.Tun.Mtu)
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithCancel(context.Background())
		handler := &Tun2socket{
			nat:        nat,
			device:     device,
			Mtu:        o.Tun.Mtu,
			ctx:        ctx,
			close:      cancel,
			tcpChannel: make(chan *netapi.StreamMeta, 100),
			udpChannel: make(chan *netapi.Packet, 100),
		}

		go handler.tcpLoop()
		go handler.udpLoop()

		return handler, nil
	}
}

func (s *Tun2socket) AcceptStream() (*netapi.StreamMeta, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case meta := <-s.tcpChannel:
		return meta, nil
	}
}

func (s *Tun2socket) AcceptPacket() (*netapi.Packet, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case packet := <-s.udpChannel:
		return packet, nil
	}
}

func (h *Tun2socket) Close() error {
	h.close()

	_ = h.nat.TCP.Close()
	_ = h.nat.UDPv2.Close()

	if goos.IsAndroid == 0 {
		return h.device.Close()
	}
	return nil
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

	select {
	case <-h.ctx.Done():
		return h.ctx.Err()
	case h.tcpChannel <- &netapi.StreamMeta{
		Source:      conn.LocalAddr(),
		Destination: conn.RemoteAddr(),
		Src:         conn,
		Address:     netapi.ParseTCPAddress(rAddrPort),
	}:
	}
	return nil
}

var errUDPAccept = errors.New("tun2socket udp accept failed")

func (h *Tun2socket) handleUDP() error {
	buf := pool.GetBytesBuffer(h.Mtu)

	n, tuple, err := h.nat.UDPv2.ReadFrom(buf.Bytes())
	if err != nil {
		return fmt.Errorf("%w: %v", errUDPAccept, err)
	}

	buf.ResetSize(0, n)

	select {
	case <-h.ctx.Done():
		return h.ctx.Err()
	case h.udpChannel <- &netapi.Packet{
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
	}:
	}

	return nil
}
