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
		// The native TUN owns its file, including on initialization failure.
		// Keep the caller's descriptor available for reconnects.
		owned, dupErr := duplicateTUNFD(sc.Fd)
		if dupErr != nil {
			return nil, fmt.Errorf("duplicate borrowed tun fd %d: %w", sc.Fd, dupErr)
		}
		file := os.NewFile(uintptr(owned), strconv.Itoa(sc.Fd))
		device, err = wun.CreateTUNFromFile(file, mtu)
		if err != nil {
			_ = file.Close()
		}
	case "tun":
		device, err = wun.CreateTUN(sc.Name, mtu)
	}
	if err != nil {
		return nil, fmt.Errorf("create tun failed: %w", err)
	}
	return NewDevice(device, offset, mtu, false), nil
}
