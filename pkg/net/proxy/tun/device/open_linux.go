package device

import (
	"fmt"
	"log/slog"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	wun "github.com/tailscale/wireguard-go/tun"
)

const (
	offset = 0
)

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
			slog.Warn("set noqueue failed", slog.String("name", sc.Name), slog.Any("err", err))
		}

		if IsGSOEnabled(wd) {
			offset = 10
		}
		device = wd
	case "fd":
		device, _, err = wun.CreateUnmonitoredTUNFromFD(sc.Fd)
	default:
		return nil, fmt.Errorf("invalid tun: %v", sc)
	}
	if err != nil {
		return nil, fmt.Errorf("create tun failed: %w", err)
	}

	return NewDevice(device, offset, mtu), nil
}
