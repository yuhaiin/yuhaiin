package dialer

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"golang.org/x/sys/windows"
)

const (
	IP_UNICAST_IF   = 31
	IPV6_UNICAST_IF = 31
)

func setSocketOptions(network, address string, c syscall.RawConn, opts *Options) (err error) {
	isUdp := isUDPSocket(network)
	if opts == nil || !isTCPSocket(network) && !isUdp {
		return
	}

	var innerErr error
	err = c.Control(func(fd uintptr) {
		if opts.listener {
			_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, SocketBufferSize)
			_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, SocketBufferSize)
		}

		if isUdp {
			// Similar to https://github.com/golang/go/issues/5834 (which involved
			// WSAECONNRESET), Windows can return a WSAENETRESET error, even on UDP
			// reads. Disable this.
			const SIO_UDP_NETRESET = windows.IOC_IN | windows.IOC_VENDOR | 15
			ret := uint32(0)
			flag := uint32(0)
			size := uint32(unsafe.Sizeof(flag))
			ioctlErr := windows.WSAIoctl(
				windows.Handle(fd),
				SIO_UDP_NETRESET,               // iocc
				(*byte)(unsafe.Pointer(&flag)), // inbuf
				size,                           // cbif
				nil,                            // outbuf
				0,                              // cbob
				&ret,                           // cbbr
				nil,                            // overlapped
				0,                              // completionRoutine
			)
			if ioctlErr != nil {
				log.Error("trySetUDPSocketOptions: could not set SIO_UDP_NETRESET", "err", ioctlErr)
			}
		}

		host, _, _ := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if ip != nil && !ip.IsGlobalUnicast() {
			return
		}

		innerErr = BindInterface(network, fd, opts.InterfaceName)

	})

	if innerErr != nil {
		err = innerErr
	}
	return
}

func bindSocketToInterface4(handle windows.Handle, index uint32) error {
	// For IPv4, this parameter must be an interface index in network byte order.
	// Ref: https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], index)
	index = *(*uint32)(unsafe.Pointer(&bytes[0]))
	return windows.SetsockoptInt(handle, windows.IPPROTO_IP, IP_UNICAST_IF, int(index))
}

func bindSocketToInterface6(handle windows.Handle, index uint32) error {
	return windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, IPV6_UNICAST_IF, int(index))
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
			err = bindSocketToInterface4(windows.Handle(fd), uint32(ifaceIndex))
		case "ip6", "tcp6", "udp6":
			err = bindSocketToInterface6(windows.Handle(fd), uint32(ifaceIndex))
			// if network == "udp6" && ip == nil {
			if network == "udp6" {
				// The underlying IP net maybe IPv4 even if the `network` param is `udp6`,
				// so we should bind socket to interface4 at the same time.
				er := bindSocketToInterface4(windows.Handle(fd), uint32(ifaceIndex))
				if er != nil {
					err = errors.Join(err, er)
				}
			}
		}
	}

	return err
}
