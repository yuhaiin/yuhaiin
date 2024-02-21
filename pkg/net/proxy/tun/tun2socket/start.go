package tun2socket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	tun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket/nat"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip"
)

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

		lis, err := StartTun2SocketGvisor(device, gateway, portal, o.Tun.Mtu)
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithCancel(context.Background())
		handler := &handler{
			listener:   lis,
			portal:     tcpip.AddrFromSlice(portal.AsSlice()),
			Mtu:        o.Tun.Mtu,
			ctx:        ctx,
			close:      cancel,
			tcpChannel: make(chan *netapi.StreamMeta, 100),
			udpChannel: make(chan *netapi.Packet, 100),
		}

		go handler.tcp()
		go handler.udp()

		return handler, nil
	}
}

type handler struct {
	Mtu      int32
	listener *Tun2Socket
	portal   tcpip.Address

	ctx   context.Context
	close context.CancelFunc

	tcpChannel chan *netapi.StreamMeta
	udpChannel chan *netapi.Packet
}

func (s *handler) AcceptStream() (*netapi.StreamMeta, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case meta := <-s.tcpChannel:
		return meta, nil
	}
}

func (s *handler) AcceptPacket() (*netapi.Packet, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case packet := <-s.udpChannel:
		return packet, nil
	}
}

func (h *handler) Close() error {
	h.close()
	return h.listener.Close()
}

func (h *handler) tcp() {
	lis := h.listener
	defer lis.TCP().Close()

	for lis.TCP().SetDeadline(time.Time{}) == nil {
		conn, err := lis.TCP().Accept()
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

func (h *handler) udp() {
	lis := h.listener
	defer lis.UDP().Close()
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

func (h *handler) handleTCP(conn net.Conn) error {
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

func (h *handler) handleUDP() error {
	buf := pool.GetBytesBuffer(h.Mtu)

	n, tuple, err := h.listener.UDP().ReadFrom(buf.Bytes())
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

			return h.listener.UDP().WriteTo(b, nat.Tuple{
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
