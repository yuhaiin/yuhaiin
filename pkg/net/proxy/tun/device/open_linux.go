package device

import (
	"fmt"
	"log/slog"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/batch"
	wun "github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

const (
	offset = 0
)

func isSocketFD(fd int) (bool, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return false, fmt.Errorf("unix.Fstat(%v,...) failed: %v", fd, err)
	}
	return (stat.Mode & unix.S_IFSOCK) == unix.S_IFSOCK, nil
}

func OpenWriter(sc netlink.TunScheme, mtu int) (netlink.Tun, error) {
	var err error
	var device wun.Device
	offset := offset
	switch sc.Scheme {
	case "tun":
		wd, err := wun.CreateTUN(sc.Name, mtu)
		if err != nil {
			return nil, fmt.Errorf("create tun failed: %w", err)
		}

		if err := netlink.SetNoqueue(sc.Name); err != nil {
			log.Warn("set noqueue failed", slog.String("name", sc.Name), slog.Any("err", err))
		}

		if IsGSOEnabled(wd) {
			offset = 10
		}
		device = wd
	case "fd":
		if err := unix.SetNonblock(sc.Fd, true); err != nil {
			return nil, fmt.Errorf("set nonblock failed: %w", err)
		}
		isSocket, _ := isSocketFD(sc.Fd)
		if isSocket {
			return batch.NewTun(sc.Fd, mtu)
		}
		return NewFd(sc.Fd, mtu)
	default:
		return nil, fmt.Errorf("invalid tun: %v", sc)
	}
	if err != nil {
		return nil, fmt.Errorf("create tun failed: %w", err)
	}

	return NewDevice(device, offset, mtu), nil
}
