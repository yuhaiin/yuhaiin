package tun

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/utils/net"
	wun "golang.zx2c4.com/wireguard/tun"
)

type TunScheme struct {
	Fd     int
	Scheme string
	Name   string
}

func ParseTunScheme(str string) (TunScheme, error) {
	scheme, name, err := net.GetScheme(str)
	if err != nil {
		return TunScheme{}, err
	}

	if len(name) < 3 {
		return TunScheme{}, fmt.Errorf("invalid tun name: %s", name)
	}

	name = name[2:]

	var fd int
	switch scheme {
	case "tun":
	case "fd":
		fd, err = strconv.Atoi(name)
		if err != nil {
			return TunScheme{}, fmt.Errorf("invalid fd: %s", name)
		}
	default:
		return TunScheme{}, fmt.Errorf("invalid tun name: %s", str)
	}

	return TunScheme{
		Scheme: scheme,
		Name:   name,
		Fd:     fd,
	}, nil
}

type Opt struct {
	Device    wun.Device
	Scheme    TunScheme
	Portal    netip.Addr
	Gateway   netip.Addr
	PortalV6  netip.Addr
	GatewayV6 netip.Addr

	Mtu int32
}

var Preload func(Opt) error
