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

func (t *Tproxy) handleTCP(c net.Conn) error {
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

	select {
	case <-t.ctx.Done():
		return t.ctx.Err()
	case t.tcpChannel <- &netapi.StreamMeta{
		Source:      c.RemoteAddr(),
		Destination: c.LocalAddr(),
		Inbound:     t.lis.Addr(),

		Src:     c,
		Address: target,
	}:
	}

	return nil
}

func (t *Tproxy) newTCP() error {
	lis, err := dialer.ListenContextWithOptions(context.TODO(), "tcp", t.host, &dialer.Options{
		MarkSymbol: func(socket int32) bool {
			return dialer.LinuxMarkSymbol(socket, 0xff) == nil
		},
	})
	if err != nil {
		return err
	}

	f, err := lis.(*net.TCPListener).SyscallConn()
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

	t.lis = lis
	t.lisAddr = lis.Addr().(*net.TCPAddr).AddrPort()

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
