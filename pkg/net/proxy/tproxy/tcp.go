package tproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
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

func handleTCP(c net.Conn, p netapi.Handler, dnsHandler netapi.DNSHandler, hijackDNS bool) error {
	z, ok := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return fmt.Errorf("not a syscall.Conn")
	}

	sysConn, err := z.SyscallConn()
	if err != nil {
		return err
	}

	if err := controlTCP(sysConn); err != nil {
		return fmt.Errorf("controlTCP failed: %w", err)
	}

	target, err := netapi.ParseSysAddr(c.LocalAddr())
	if err != nil {
		return fmt.Errorf("parse local addr failed: %w", err)
	}
	if isHandleDNS(target.Port().Port()) && hijackDNS {
		return dnsHandler.HandleTCP(context.Background(), c)
	}

	p.Stream(context.TODO(), &netapi.StreamMeta{
		Source:      c.RemoteAddr(),
		Destination: c.LocalAddr(),
		Inbound:     c.RemoteAddr(),

		Src:     c,
		Address: target,
	})
	return nil
}
