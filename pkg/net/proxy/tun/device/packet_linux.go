package device

import (
	"fmt"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"golang.org/x/sys/unix"
)

// OpenPacketWriter keeps complete IP packets on plain/Android descriptors and
// negotiates TCP offloads on Linux VNET descriptors. Supplied fds are duplicated;
// their framing is inspected, never changed. A newly created TUN falls back to
// plain packets when VNET or checksum negotiation is unavailable.
func OpenPacketWriter(sc netlink.TunScheme, mtu int) (netlink.Tun, error) {
	var fd int
	var err error
	switch sc.Scheme {
	case "tun":
		fd, err = openPacketFD(sc.Name, true)
		if err == nil {
			if d, offloadErr := newOffloadTUN(fd, mtu, sc.Name); offloadErr == nil {
				return d, nil
			}
			_ = unix.Close(fd)
		}
		fd, err = openPacketFD(sc.Name, false)
		if err != nil {
			return nil, err
		}
	case "fd":
		fd, err = duplicateTUNFD(sc.Fd)
		if err != nil {
			return nil, fmt.Errorf("duplicate packet TUN fd: %w", err)
		}
		ifr, err := unix.NewIfreq("")
		if err == nil {
			err = unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr)
		}
		if err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("inspect packet TUN fd: %w", err)
		}
		flags := ifr.Uint16()
		if flags&unix.IFF_NO_PI == 0 || flags&unix.IFF_TUN == 0 || flags&unix.IFF_TAP != 0 {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("lightweight requires an IP-only TUN fd without packet-info headers")
		}
		if flags&unix.IFF_VNET_HDR != 0 {
			d, err := newOffloadTUN(fd, mtu, sc.Name)
			if err != nil {
				_ = unix.Close(fd)
			}
			return d, err
		}
	default:
		return nil, fmt.Errorf("unsupported packet TUN scheme %q", sc.Scheme)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &Fd{fd: os.NewFile(uintptr(fd), sc.Name), mtu: mtu}, nil
}

func openPacketFD(name string, vnet bool) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	ifr, err := unix.NewIfreq(name)
	if err == nil {
		flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if vnet {
			flags |= unix.IFF_VNET_HDR
		}
		ifr.SetUint16(flags)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	}
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}
