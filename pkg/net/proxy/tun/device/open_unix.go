//go:build unix && !aix && !ppc64 && !linux

package device

import (
	"fmt"
	"os"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	wun "github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

const (
	offset = 4
)

func OpenWriter(sc netlink.TunScheme, mtu int) (netlink.Tun, error) {
	if len(sc.Name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name too long: %s", sc.Name)
	}

	var device wun.Device
	var err error
	switch sc.Scheme {
	case "fd":
		device, err = wun.CreateTUNFromFile(os.NewFile(uintptr(sc.Fd), strconv.Itoa(sc.Fd)), mtu)
	case "tun":
		device, err = wun.CreateTUN(sc.Name, mtu)
	}
	if err != nil {
		return nil, fmt.Errorf("create tun failed: %w", err)
	}
	return NewDevice(device, offset, mtu, false), nil
}
