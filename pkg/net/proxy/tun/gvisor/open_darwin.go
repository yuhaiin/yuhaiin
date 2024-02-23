package tun

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"golang.org/x/sys/unix"
	wun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	offset = 4
)

func open(sc TunScheme, driver listener.TunEndpointDriver, mtu int) (_ stack.LinkEndpoint, err error) {
	iwc, err := OpenWriter(sc, mtu)
	if err != nil {
		return nil, fmt.Errorf("open tun failed: %w", err)
	}

	endpoint := NewEndpoint(&wgWriter{iwc}, uint32(mtu), "")
	return endpoint, nil
}

func OpenWriter(sc TunScheme, mtu int) (io.ReadWriteCloser, error) {
	if len(sc.Name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name too long: %s", sc.Name)
	}

	var iwc io.ReadWriteCloser
	switch sc.Scheme {
	case "fd":
		iwc = os.NewFile(uintptr(sc.Fd), strconv.Itoa(sc.Fd))
	case "tun":
		device, err := wun.CreateTUN(sc.Name, mtu)
		if err != nil {
			return nil, fmt.Errorf("create tun failed: %w", err)
		}
		iwc = newWgTun(device)
	}

	return iwc, nil
}
