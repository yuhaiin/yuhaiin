//go:build unix && !linux

package tun

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
	wun "golang.zx2c4.com/wireguard/tun"
)

const (
	offset = 4
)

func OpenWriter(sc TunScheme, mtu int) (io.ReadWriteCloser, error) {
	if len(sc.Name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name too long: %s", sc.Name)
	}

	var iwc io.ReadWriteCloser
	switch sc.Scheme {
	case "fd":
		iwc = newHiddenCloser(os.NewFile(uintptr(sc.Fd), strconv.Itoa(sc.Fd)))
	case "tun":
		device, err := wun.CreateTUN(sc.Name, mtu)
		if err != nil {
			return nil, fmt.Errorf("create tun failed: %w", err)
		}
		iwc = newWgTun(device)
	}

	return iwc, nil
}
