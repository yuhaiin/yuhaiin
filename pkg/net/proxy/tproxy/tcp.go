//go:build !windows
// +build !windows

package tproxy

import (
	"fmt"
	"net"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	is "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	lis "github.com/Asutorufa/yuhaiin/pkg/net/proxy/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

func controlTCP(c syscall.RawConn) error {
	var fn = func(s uintptr) {
		err := syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
		if err != nil {
			log.Warningf("set socket with SOL_IP,IP_TRANSPARENT failed: %v", err)
		}

		v, err := syscall.GetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT)
		if err != nil {
			log.Warningf("get socket with SOL_IP, IP_TRANSPARENT failed: %v", err)
		} else {
			log.Debugf("value of IP_TRANSPARENT option is: %d", int(v))
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
		return fmt.Errorf("controlTCP failed: %v", err)
	}

	addr, err := proxy.ParseSysAddr(c.LocalAddr())
	if err != nil {
		return fmt.Errorf("parse local addr failed: %v", err)
	}
	r, err := p.Conn(addr)
	if err != nil {
		return fmt.Errorf("get conn failed: %v", err)
	}

	utils.Relay(c, r)
	return nil
}

func newTCPServer(h string, dialer proxy.Proxy) (is.Server, error) {
	return lis.NewTCPServer(h, func(c net.Conn) {
		if err := handleTCP(c, dialer); err != nil {
			log.Errorf("handleTCP failed: %v", err)
		}
	})
}
