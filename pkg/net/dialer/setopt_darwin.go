package dialer

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// syscall.TCP_KEEPINTVL is missing on some darwin architectures.
const sysTCP_KEEPINTVL = 0x101

func setSocketOptions(network, address string, c syscall.RawConn, opts *Options) (err error) {
	if opts == nil || !isTCPSocket(network) && !isUDPSocket(network) {
		return
	}

	var innerErr error
	err = c.Control(func(fd uintptr) {
		if opts.listener {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, SocketBufferSize)
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, SocketBufferSize)
		}

		// if isTCPSocket(network) {
		// _ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, sysTCP_KEEPINTVL, int(15))
		// _ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPALIVE, int(180))
		// _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
		// }

		host, _, _ := net.SplitHostPort(address)
		if ip := net.ParseIP(host); ip != nil && !ip.IsGlobalUnicast() {
			return
		}

		if opts.listener {
			return
		}

		innerErr = BindInterface(network, fd, opts.InterfaceName)

	})

	if innerErr != nil {
		err = innerErr
	}
	return
}

func BindInterface(network string, fd uintptr, ifaceName string) error {
	ifaceIndex := 0
	if ifaceName != "" {
		if iface, err := net.InterfaceByName(ifaceName); err == nil {
			ifaceIndex = iface.Index
		}
	}

	var err error
	if ifaceIndex != 0 {
		switch network {
		case "ip4", "tcp4", "udp4":
			err = unix.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, ifaceIndex)
		case "ip6", "tcp6", "udp6":
			err = unix.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, ifaceIndex)
		}
	}

	return err
}
