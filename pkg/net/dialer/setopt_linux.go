package dialer

import (
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
		if opts.listener {
			// Set up to *mem_max
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, SocketBufferSize)
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, SocketBufferSize)

			// Set beyond *mem_max if CAP_NET_ADMIN
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, SocketBufferSize)
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, SocketBufferSize)
		}
		innerErr = applySocketRouting(network, address, fd, opts)
	})

	if innerErr != nil {
		err = innerErr
	}
	return
}

func BindInterface(network string, fd uintptr, ifaceName string) error {
	if ifaceName != "" {
		// log.Println("dialer: set socket option: SO_BINDTODEVICE", opts.InterfaceName)
		return unix.BindToDevice(int(fd), ifaceName)
	}

	return nil
}
