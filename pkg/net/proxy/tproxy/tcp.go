package tproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
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

	if addrPort := target.AddrPort(context.TODO()); addrPort.Err == nil && addrPort.V.Compare(t.lisAddr) == 0 {
		return fmt.Errorf("local addr and remote addr are same")
	}

	t.SendStream(&netapi.StreamMeta{
		Source:      c.RemoteAddr(),
		Destination: c.LocalAddr(),
		Inbound:     netapi.ParseAddrPort(statistic.Type_tcp, t.lisAddr),

		Src:     c,
		Address: target,
	})

	return nil
}

func (t *Tproxy) newTCP() error {
	lis, err := t.lis.Stream(t.Context())
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
