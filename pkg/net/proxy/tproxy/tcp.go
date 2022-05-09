//go:build !windows
// +build !windows

package tproxy

import (
	"log"
	"net"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	is "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	lis "github.com/Asutorufa/yuhaiin/pkg/net/proxy/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

func controlTCP(network, address string, c syscall.RawConn) error {
	var fn = func(s uintptr) {
		err := syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
		if err != nil {
			log.Printf("set socket with SOL_IP,IP_TRANSPARENT failed: %v", err)
		}

		v, err := syscall.GetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT)
		if err != nil {
			log.Printf("get socket with SOL_IP, IP_TRANSPARENT failed: %v", err)
		} else {
			log.Printf("value of IP_TRANSPARENT option is: %d", int(v))
		}
	}

	if err := c.Control(fn); err != nil {
		return err
	}

	return nil
}

func handleTCP(c net.Conn, p proxy.Proxy) {
	r, err := p.Conn(c.LocalAddr().String())
	if err != nil {
		log.Printf("get conn failed: %v", err)
		return
	}

	utils.Relay(c, r)
}

func newTCPServer(h string, dialer proxy.Proxy) (is.Server, error) {
	return lis.NewTCPServer(h, func(c net.Conn) { handleTCP(c, dialer) },
		lis.TCPWithListenConfig(net.ListenConfig{Control: controlTCP}))
}
