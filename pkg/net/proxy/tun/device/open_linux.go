package device

import (
	"fmt"
	"log/slog"
	"syscall"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	wun "github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

const (
	offset = 0
)

func OpenWriter(sc netlink.TunScheme, mtu int) (netlink.Tun, error) {
	var err error
	var device wun.Device
	offset := offset
	gsoEnabled := false
	switch sc.Scheme {
	case "tun":
		wd, err := wun.CreateTUN(sc.Name, mtu)
		if err != nil {
			return nil, fmt.Errorf("create tun failed: %w", err)
		}

		if err := netlink.SetNoqueue(sc.Name); err != nil {
			log.Warn("set noqueue failed", slog.String("name", sc.Name), slog.Any("err", err))
		}

		gsoEnabled = IsGSOEnabled(int(wd.File().Fd()))
		if gsoEnabled {
			offset = 10
			log.Info("tun gso enabled", slog.String("name", sc.Name))
		}
		device = wd
	case "fd":
		gsoEnabled = IsGSOEnabled(sc.Fd)
		if !gsoEnabled {
			return NewFd(sc.Fd, mtu)
		}

		device, _, err = wun.CreateUnmonitoredTUNFromFD(sc.Fd)

	default:
		return nil, fmt.Errorf("invalid tun: %v", sc)
	}
	if err != nil {
		return nil, fmt.Errorf("create tun failed: %w", err)
	}

	return NewDevice(device, offset, mtu, gsoEnabled), nil
}

func IsGSOEnabled(fd int) bool {
	name, err := Name(fd)
	if err != nil {
		return false
	}

	var ifr *unix.Ifreq
	ifr, err = unix.NewIfreq(name)
	if err != nil {
		return false
	}
	err = unix.IoctlIfreq(int(fd), unix.TUNGETIFF, ifr)
	if err != nil {
		return false
	}
	got := ifr.Uint16()
	return got&unix.IFF_VNET_HDR != 0
}

func Name(fd int) (string, error) {
	const ifReqSize = unix.IFNAMSIZ + 64

	var ifr [ifReqSize]byte
	var errno syscall.Errno
	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNGETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return "", fmt.Errorf("failed to get name of TUN device: %w", errno)
	}
	return unix.ByteSliceToString(ifr[:]), nil
}
