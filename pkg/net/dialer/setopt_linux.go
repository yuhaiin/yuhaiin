//go:build linux
// +build linux

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

		host, _, _ := net.SplitHostPort(address)
		if ip := net.ParseIP(host); ip != nil && !ip.IsGlobalUnicast() {
			return
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
