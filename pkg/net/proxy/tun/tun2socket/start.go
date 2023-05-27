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
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
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
		portal:       portal,
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
	portal       netip.Addr
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
	rAddrPort := conn.RemoteAddr().(*net.TCPAddr).AddrPort() // dst

	if rAddrPort.Addr().IsLoopback() {
		return nil
	}

	if h.isHandleDNS(rAddrPort) {
		return h.DNSHandler.HandleTCP(context.TODO(), conn)
	}

	h.handler.Stream(context.TODO(), &proxy.StreamMeta{
		Source:      conn.LocalAddr(),
		Destination: conn.RemoteAddr(),
		Src:         conn,
		Address:     proxy.ParseAddrPort(statistic.Type_tcp, rAddrPort),
	})

	return nil
}

var errUDPAccept = errors.New("tun2socket udp accept failed")

func (h *handler) handleUDP(server proxy.Handler, lis *Tun2Socket, buf []byte) error {
	n, src, dst, err := lis.UDP().ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("%w: %v", errUDPAccept, err)
	}

	zbuf := buf[:n]

	if h.isHandleDNS(dst) {
		resp, err := h.DNSHandler.Do(context.TODO(), zbuf)
		if err != nil {
			return err
		}
		_, err = lis.UDP().WriteTo(resp, dst, src)
		return err
	}

	server.Packet(context.TODO(),
		&proxy.Packet{
			Src:     net.UDPAddrFromAddrPort(src),
			Dst:     proxy.ParseAddrPort(statistic.Type_udp, dst),
			Payload: zbuf,
			WriteBack: func(b []byte, addr net.Addr) (int, error) {
				address, err := proxy.ParseSysAddr(addr)
				if err != nil {
					return 0, err
				}

				daddr, err := address.AddrPort(context.TODO())
				if err != nil {
					return 0, err
				}

				return lis.UDP().WriteTo(b, daddr, src)
			},
		},
	)
	return nil
}

func (h *handler) isHandleDNS(addr netip.AddrPort) bool {
	if addr.Port() == 53 && (h.DnsHijacking || addr.Addr() == h.portal) {
		return true
	}
	return false
}
