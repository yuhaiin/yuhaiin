package tun

import (
	"fmt"
	"io"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	wun "golang.zx2c4.com/wireguard/tun"
	gun "gvisor.dev/gvisor/pkg/tcpip/link/tun"
)

const (
	offset = 0
)

func OpenWriter(sc netlink.TunScheme, mtu int) (io.ReadWriteCloser, error) {
	var err error
	var device wun.Device
	switch sc.Scheme {
	case "tun":
		device, err = createTUN(sc.Name, mtu)
	case "fd":
		device, _, err = wun.CreateUnmonitoredTUNFromFD(sc.Fd)
	default:
		return nil, fmt.Errorf("invalid tun: %v", sc)
	}
	if err != nil {
		return nil, fmt.Errorf("create tun failed: %w", err)
	}

	return newWgReadWriteCloser(device), nil
}

func createTUN(name string, mtu int) (wun.Device, error) {
	nfd, err := gun.Open(name)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}

	fd := os.NewFile(uintptr(nfd), "/dev/net/tun")
	return wun.CreateTUNFromFile(fd, mtu)
}
