package dialer

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

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
		innerErr = applySocketRouting(network, address, fd, opts)
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
		switch socketFamily(network, fd) {
		case unix.AF_INET:
			err = unix.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, ifaceIndex)
		case unix.AF_INET6:
			// Also scopes IPv4-mapped traffic of a dual-stack socket.
			err = unix.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, ifaceIndex)
		}
	}

	return err
}

// socketFamily resolves the address family of fd. A family-less network such
// as "udp" or "tcp" may be either an AF_INET socket or a dual-stack AF_INET6
// one, so ask the socket itself instead of leaving it unbound.
func socketFamily(network string, fd uintptr) int {
	switch network {
	case "ip4", "tcp4", "udp4":
		return unix.AF_INET
	case "ip6", "tcp6", "udp6":
		return unix.AF_INET6
	}
	sa, err := unix.Getsockname(int(fd))
	if err != nil {
		return 0
	}
	switch sa.(type) {
	case *unix.SockaddrInet4:
		return unix.AF_INET
	case *unix.SockaddrInet6:
		return unix.AF_INET6
	}
	return 0
}
