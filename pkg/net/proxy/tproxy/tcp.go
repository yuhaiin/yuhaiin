//go:build linux

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

func (t *Tproxy) handleTCP(c net.Conn) error {
	target, err := netapi.ParseSysAddr(c.LocalAddr())
	if err != nil {
		return fmt.Errorf("parse local addr failed: %w", err)
	}

	if ip, err := dialer.ResolverIP(context.TODO(), target); err == nil && ip.Equal(t.lisAddr.IP) && int(target.Port()) == t.lisAddr.Port {
		return fmt.Errorf("local addr and remote addr are same")
	}

	t.handler.HandleStream(&netapi.StreamMeta{
		Source:      c.RemoteAddr(),
		Destination: c.LocalAddr(),
		Inbound:     netapi.ParseIPAddr("tcp", t.lisAddr.IP, uint16(t.lisAddr.Port)),
		Src:         c,
		Address:     target,
	})

	return nil
}

func (t *Tproxy) newTCP() error {
	lis, err := t.lis.Stream(t.ctx)
	if err != nil {
		return err
	}

	tcpLis, ok := lis.(*net.TCPListener)
	if !ok {
		lis.Close()
		return fmt.Errorf("listen is not tcp listener")
	}

	f, err := tcpLis.SyscallConn()
	if err != nil {
		lis.Close()
		return err
	}

	err = controlTCP(f)
	if err != nil {
		lis.Close()
		return err
	}

	log.Info("new tproxy tcp server", "host", lis.Addr())

	t.lisAddr = lis.Addr().(*net.TCPAddr)

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

	return nil
}
