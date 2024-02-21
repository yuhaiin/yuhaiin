package tun

import (
	"fmt"
	"io"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	wun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	offset = 0
)

func open(sc TunScheme, _ listener.TunEndpointDriver, mtu int) (_ stack.LinkEndpoint, err error) {
	iwc, err := OpenWriter(sc, mtu)
	if err != nil {
		return nil, fmt.Errorf("open tun failed: %w", err)
	}

	endpoint := NewEndpoint(&wgWriter{iwc}, uint32(mtu), "")
	return endpoint, nil
}

func OpenWriter(sc TunScheme, mtu int) (io.ReadWriteCloser, error) {
	if sc.Scheme != "tun" {
		return nil, fmt.Errorf("invalid tun: %v", sc)
	}

	device, err := wun.CreateTUN(sc.Name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun failed: %w", err)
	}

	return newWgTun(device), nil
}
