package tun

import (
	"fmt"
	"io"

	wun "golang.zx2c4.com/wireguard/tun"
)

const (
	offset = 0
)

func OpenWriter(sc TunScheme, mtu int) (io.ReadWriteCloser, error) {
	var err error
	var device wun.Device
	switch sc.Scheme {
	case "tun":
		device, err = wun.CreateTUN(sc.Name, mtu)
	case "fd":
		device, _, err = wun.CreateUnmonitoredTUNFromFD(sc.Fd)
	default:
		return nil, fmt.Errorf("invalid tun: %v", sc)
	}
	if err != nil {
		return nil, fmt.Errorf("create tun failed: %w", err)
	}

	return newWgTun(device), nil
}
