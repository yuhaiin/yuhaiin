package gvisor

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var openFD func(sc netlink.TunScheme, mtu int) (stack.LinkEndpoint, error)

func Open(sc netlink.TunScheme, driver device.Driver, mtu int) (_ stack.LinkEndpoint, err error) {
	if driver == device.DriverFDBased && openFD != nil {
		return openFD(sc, mtu)
	}

	w, err := device.OpenWriter(sc, mtu)
	if err != nil {
		return nil, fmt.Errorf("open tun failed: %w", err)
	}
	return NewEndpoint(w), nil
}
