package tun2socket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket/nat"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func New(o *listener.Opts[*listener.Protocol_Tun]) (*Tun2Socket, error) {
	gateway, gerr := netip.ParseAddr(o.Protocol.Tun.Gateway)
	portal, perr := netip.ParseAddr(o.Protocol.Tun.Portal)
	if gerr != nil || perr != nil {
		return nil, fmt.Errorf("gateway or portal is invalid")
	}

	device, err := openDevice(o.Protocol.Tun.Name)
	if err != nil {
		return nil, fmt.Errorf("open tun device failed: %w", err)
	}

	lis, err := StartTun2SocketGvisor(device, gateway, portal, o.Protocol.Tun.Mtu)
	if err != nil {
		return nil, err
	}

	handler := &handler{
		listener:     lis,
		portal:       tcpip.AddrFromSlice(portal.AsSlice()),
		DnsHijacking: o.Protocol.Tun.DnsHijacking,
		Mtu:          o.Protocol.Tun.Mtu,
		handler:      o.Handler,
		DNSHandler:   o.DNSHandler,
	}

	go handler.tcp()
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		go handler.udp(o.Handler)
	}

	return lis, nil
}

type handler struct {
	DnsHijacking bool
	Mtu          int32
	listener     *Tun2Socket
	portal       tcpip.Address
	handler      proxy.Handler
	DNSHandler   proxy.DNSHandler
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
				if errors.Is(err, proxy.ErrBlocked) {
					log.Debug(err.Error())
				} else {
					log.Error("handle tcp failed", "err", err)
				}
			}
		}()

	}
}

func (h *handler) udp(server proxy.Handler) {
	lis := h.listener
	defer lis.UDP().Close()
	buf := pool.GetBytes(h.Mtu)
	defer pool.PutBytes(buf)
	for {
		if err := h.handleUDP(server, lis, buf); err != nil {
			if errors.Is(err, proxy.ErrBlocked) {
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

	if h.isHandleDNS(tcpip.AddrFromSlice(rAddrPort.IP), uint16(rAddrPort.Port)) {
		return h.DNSHandler.HandleTCP(context.TODO(), conn)
	}

	h.handler.Stream(context.TODO(), &proxy.StreamMeta{
		Source:      conn.LocalAddr(),
		Destination: conn.RemoteAddr(),
		Src:         conn,
		Address:     proxy.ParseTCPAddress(rAddrPort),
	})

	return nil
}

var errUDPAccept = errors.New("tun2socket udp accept failed")

func (h *handler) handleUDP(server proxy.Handler, lis *Tun2Socket, buf []byte) error {
	n, tuple, err := lis.UDP().ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("%w: %v", errUDPAccept, err)
	}

	zbuf := buf[:n]

	if h.isHandleDNS(tuple.DestinationAddr, tuple.DestinationPort) {
		resp, err := h.DNSHandler.Do(context.TODO(), zbuf)
		if err != nil {
			return err
		}
		_, err = lis.UDP().WriteTo(resp, tuple)
		return err
	}

	server.Packet(context.TODO(),
		&proxy.Packet{
			Src: &net.UDPAddr{
				IP:   net.IP(tuple.SourceAddr.AsSlice()),
				Port: int(tuple.SourcePort),
			},
			Dst: proxy.ParseUDPAddr(&net.UDPAddr{
				IP:   net.IP(tuple.DestinationAddr.AsSlice()),
				Port: int(tuple.DestinationPort),
			}),
			Payload: zbuf,
			WriteBack: func(b []byte, addr net.Addr) (int, error) {
				address, err := proxy.ParseSysAddr(addr)
				if err != nil {
					return 0, err
				}

				daddr, err := address.IP(context.TODO())
				if err != nil {
					return 0, err
				}

				return lis.UDP().WriteTo(b, nat.Tuple{
					DestinationAddr: tcpip.AddrFromSlice(daddr),
					DestinationPort: address.Port().Port(),
					SourceAddr:      tuple.SourceAddr,
					SourcePort:      tuple.SourcePort,
				})
			},
		},
	)
	return nil
}

func (h *handler) isHandleDNS(addr tcpip.Address, port uint16) bool {
	if port == 53 && (h.DnsHijacking || addr == h.portal) {
		return true
	}
	return false
}
