//go:build linux
// +build linux

package tproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	is "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
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

func handleTCP(c net.Conn, p proxy.Proxy) error {
	z, ok := c.(interface{ SyscallConn() syscall.RawConn })
	if !ok {
		return fmt.Errorf("not a syscall.Conn")
	}

	if err := controlTCP(z.SyscallConn()); err != nil {
		return fmt.Errorf("controlTCP failed: %w", err)
	}

	addr, err := proxy.ParseSysAddr(c.LocalAddr())
	if err != nil {
		return fmt.Errorf("parse local addr failed: %w", err)
	}
	r, err := p.Conn(context.TODO(), addr)
	if err != nil {
		return fmt.Errorf("get conn failed: %w", err)
	}

	relay.Relay(c, r)
	return nil
}

func newTCPServer(h string, dialer proxy.Proxy) (is.Server, error) {
	return NewTCPServer(h, func(c net.Conn) {
		if err := handleTCP(c, dialer); err != nil {
			log.Error("handleTCP failed", "err", err)
		}
	})
}
