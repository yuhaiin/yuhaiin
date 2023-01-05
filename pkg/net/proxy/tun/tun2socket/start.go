package tun2socket

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5s "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

func New(natTable *s5s.NatTable, o *listener.Opts[*listener.Protocol_Tun]) (*Tun2Socket, error) {
	gateway, ger := netip.ParseAddr(o.Protocol.Tun.Gateway)
	portal, per := netip.ParseAddr(o.Protocol.Tun.Portal)
	if ger != nil || per != nil {
		return nil, fmt.Errorf("gateway or portal is invalid")
	}

	device, err := openDevice(o.Protocol.Tun.Name)
	if err != nil {
		return nil, fmt.Errorf("open tun device failed: %w", err)
	}

	lis, err := StartTun2Socket(device, gateway, portal)
	if err != nil {
		return nil, err
	}

	tcp := func() {
		defer lis.TCP().Close()

		for lis.TCP().SetDeadline(time.Time{}) == nil {
			conn, err := lis.TCP().Accept()
			if err != nil {
				log.Errorln("tun2socket tcp accept failed:", err)
				continue
			}

			go func() {
				if err = handleTCP(o, conn); err != nil {
					log.Errorln("handle tcp failed:", err)
				}
			}()

		}

	}

	udp := func() {
		defer lis.UDP().Close()
		buf := pool.GetBytes(65535)
		defer pool.PutBytes(buf)
		for {
			if err = handleUDP(o, natTable, lis, buf); err != nil {
				log.Errorln("handle udp failed:", err)
				if errors.Is(err, errUDPAccept) {
					return
				}
			}
		}
	}

	go tcp()
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		go udp()
	}

	return lis, nil
}

func handleTCP(o *listener.Opts[*listener.Protocol_Tun], conn net.Conn) error {
	defer conn.Close()

	// lAddrPort := conn.LocalAddr().(*net.TCPAddr).AddrPort()  // source
	rAddrPort := conn.RemoteAddr().(*net.TCPAddr).AddrPort() // dst

	if rAddrPort.Addr().IsLoopback() {
		return nil
	}

	addr := proxy.ParseAddressSplit(statistic.Type_tcp, rAddrPort.Addr().String(), proxy.ParsePort(rAddrPort.Port()))
	addr.WithValue(proxy.SourceKey{}, conn.LocalAddr())
	addr.WithValue(proxy.DestinationKey{}, conn.RemoteAddr())

	if IsHandleDNS(o, addr.Hostname(), addr.Port().Port()) {
		return o.DNSServer.HandleTCP(conn)
	}

	lconn, err := o.Dialer.Conn(addr)
	if err != nil {
		return err
	}
	defer lconn.Close()

	relay.Relay(conn, lconn)
	return nil
}

var errUDPAccept = errors.New("tun2socket udp accept failed")

func handleUDP(o *listener.Opts[*listener.Protocol_Tun], natTable *s5s.NatTable, lis *Tun2Socket, buf []byte) error {
	n, src, dst, err := lis.UDP().ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("%w: %v", errUDPAccept, err)
	}

	zbuf := buf[:n]

	addr := proxy.ParseAddressSplit(statistic.Type_udp, dst.Addr().String(), proxy.ParsePort(dst.Port()))

	if IsHandleDNS(o, addr.Hostname(), addr.Port().Port()) {
		resp, err := o.DNSServer.Do(zbuf)
		if err != nil {
			return err
		}
		_, err = lis.UDP().WriteTo(resp, dst, src)
		return err
	}

	return natTable.Write(zbuf, net.UDPAddrFromAddrPort(src), addr,
		func(b []byte, addr net.Addr) (int, error) { return lis.UDP().WriteTo(b, dst, src) })
}

func IsHandleDNS(opt *listener.Opts[*listener.Protocol_Tun], hostname string, port uint16) bool {
	if port == 53 && (opt.Protocol.Tun.DnsHijacking || hostname == opt.Protocol.Tun.Portal) {
		return true
	}
	return false
}
