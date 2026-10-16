package device

import (
	"fmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"golang.org/x/sys/unix"
	"os"
)

// OpenPacketWriter deliberately negotiates ordinary IP packets. It leaves the
// legacy GSO/multiqueue opener unchanged. A supplied VNET fd is rejected rather
// than treating virtio metadata or partial checksums as validated wire packets.
func OpenPacketWriter(sc netlink.TunScheme, mtu int) (netlink.Tun, error) {
	fd := sc.Fd
	owned := false
	switch sc.Scheme {
	case "tun":
		var err error
		fd, err = unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		owned = true
		ifr, err := unix.NewIfreq(sc.Name)
		if err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
	case "fd":
		ifr, err := unix.NewIfreq("")
		if err != nil {
			return nil, err
		}
		if err = unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr); err != nil {
			return nil, fmt.Errorf("inspect packet TUN fd: %w", err)
		}
		flags := ifr.Uint16()
		if flags&unix.IFF_VNET_HDR != 0 || flags&unix.IFF_NO_PI == 0 || flags&unix.IFF_TUN == 0 {
			return nil, fmt.Errorf("lightweight requires an IP-only TUN fd without VNET/offload headers")
		}
	default:
		return nil, fmt.Errorf("unsupported packet TUN scheme %q", sc.Scheme)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		if owned {
			_ = unix.Close(fd)
		}
		return nil, err
	}
	return &Fd{fd: os.NewFile(uintptr(fd), sc.Name), mtu: mtu}, nil
}
