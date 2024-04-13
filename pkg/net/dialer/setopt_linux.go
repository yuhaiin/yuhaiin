package dialer

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func LinuxMarkSymbol(fd int32, mark int) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
}

func setSocketOptions(network, address string, c syscall.RawConn, opts *Options) (err error) {
	if opts == nil || !isTCPSocket(network) && !isUDPSocket(network) {
		return
	}

	var innerErr error
	err = c.Control(func(fd uintptr) {
		if opts.MarkSymbol != nil {
			opts.MarkSymbol(int32(fd))
		}

		if opts.listener {
			// Set up to *mem_max
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, SocketBufferSize)
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, SocketBufferSize)

			// Set beyond *mem_max if CAP_NET_ADMIN
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, SocketBufferSize)
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, SocketBufferSize)

			return
		}

		if isTCPSocket(network) {
			// https://github.com/golang/go/issues/48622
			/*
				TCP_KEEPIDLE=180
				TCP_KEEPINTVL=15
				TCP_KEEPCNT=2
			*/
			// _ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, int(15))
			// _ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, int(180))
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
			// _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 0)
		}

		if (opts.InterfaceName == "" && opts.InterfaceIndex != 0) || opts.InterfaceName != "" {
			host, _, _ := net.SplitHostPort(address)
			if ip := net.ParseIP(host); ip != nil && !ip.IsGlobalUnicast() {
				return
			}
		}

		if opts.InterfaceName == "" && opts.InterfaceIndex != 0 {
			if iface, err := net.InterfaceByIndex(opts.InterfaceIndex); err == nil {
				opts.InterfaceName = iface.Name
			}
		}

		if opts.InterfaceName != "" {
			// log.Println("dialer: set socket option: SO_BINDTODEVICE", opts.InterfaceName)
			if innerErr = unix.BindToDevice(int(fd), opts.InterfaceName); innerErr != nil {
				return
			}
		}

	})

	if innerErr != nil {
		err = innerErr
	}
	return
}
