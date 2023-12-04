package tproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	cl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func init() {
	dialer.DefaultMarkSymbol = func(socket int32) bool {
		return dialer.LinuxMarkSymbol(socket, 0xff) == nil
	}
}

func controlTCP(c syscall.RawConn) error {
	var fn = func(s uintptr) {
		err := syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
		if err != nil {
			log.Warn("set socket with SOL_IP,IP_TRANSPARENT failed", "err", err)
		}

		v, err := syscall.GetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT)
		if err != nil {
			log.Warn("get socket with SOL_IP, IP_TRANSPARENT failed", "err", err)
		} else {
			log.Debug("value of IP_TRANSPARENT", "options", int(v))
		}
	}

	if err := c.Control(fn); err != nil {
		return err
	}

	return nil
}

func (t *tcpserver) handleTCP(c net.Conn) error {
	target, err := netapi.ParseSysAddr(c.LocalAddr())
	if err != nil {
		return fmt.Errorf("parse local addr failed: %w", err)
	}

	addrPort, err := target.AddrPort(context.TODO())
	if err == nil {
		if addrPort.Addr().Unmap() == t.lisAddr.Addr().Unmap() &&
			addrPort.Port() == t.lisAddr.Port() {
			return fmt.Errorf("local addr and remote addr are same")
		}
	}

	if isHandleDNS(target.Port().Port()) && t.hijackDNS {
		defer c.Close()
		ctx := context.TODO()
		if t.fakeip {
			ctx = context.WithValue(ctx, netapi.ForceFakeIP{}, true)
		}

		return t.dns.HandleTCP(ctx, c)
	}

	t.dialer.Stream(context.TODO(), &netapi.StreamMeta{
		Source:      c.RemoteAddr(),
		Destination: c.LocalAddr(),
		Inbound:     t.lis.Addr(),

		Src:     c,
		Address: target,
	})
	return nil
}

type tcpserver struct {
	hijackDNS bool
	fakeip    bool
	dialer    netapi.Handler
	dns       netapi.DNSHandler
	lis       net.Listener

	lisAddr netip.AddrPort
}

func (t *tcpserver) Close() error { return t.lis.Close() }

func newTCP(opt *cl.Opts[*cl.Protocol_Tproxy]) (*tcpserver, error) {
	lis, err := dialer.ListenContextWithOptions(context.TODO(), "tcp", opt.Protocol.Tproxy.GetHost(), &dialer.Options{
		MarkSymbol: func(socket int32) bool {
			return dialer.LinuxMarkSymbol(socket, 0xff) == nil
		},
	})
	if err != nil {
		return nil, err
	}

	f, err := lis.(*net.TCPListener).SyscallConn()
	if err != nil {
		lis.Close()
		return nil, err
	}

	err = controlTCP(f)
	if err != nil {
		lis.Close()
		return nil, err
	}

	t := &tcpserver{
		dialer:    opt.Handler,
		dns:       opt.DNSHandler,
		hijackDNS: opt.Protocol.Tproxy.GetDnsHijacking(),
		fakeip:    opt.Protocol.Tproxy.GetForceFakeip(),
		lis:       lis,
		lisAddr:   lis.Addr().(*net.TCPAddr).AddrPort(),
	}

	log.Info("new tproxy tcp server", "host", lis.Addr())

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Error("tcp server accept failed", "err", err)
				break
			}

			go func() {
				if err := t.handleTCP(conn); err != nil {
					log.Error("tcp server handle failed", "err", err)
				}
			}()
		}
	}()

	return t, nil
}
