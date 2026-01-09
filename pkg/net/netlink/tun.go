package netlink

import (
	"fmt"
	"io"
	"net/netip"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	wun "github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Platform struct {
	Darwin Darwin
}

type Darwin struct {
	// network service name
	// which can be found by `networksetup -listallnetworkservices`
	NetworkService string
}

type Options struct {
	Endpoint     stack.LinkEndpoint
	Device       Tun
	Platform     Platform
	Interface    TunScheme
	Inet6Address []netip.Prefix
	Inet4Address []netip.Prefix
	Routes       []netip.Prefix
	MTU          int
}

type Tun interface {
	Tun() wun.Device
	Write(bufs [][]byte) (int, error)
	Read(bufs [][]byte, sizes []int) (n int, err error)
	io.Closer
	Offset() int
	MTU() int
}

func (o *Options) V4Address() netip.Prefix {
	if len(o.Inet4Address) > 0 {
		return o.Inet4Address[0]
	}
	return netip.Prefix{}
}

func (o *Options) V4Contains(addr netip.Addr) bool {
	for _, v := range o.Inet4Address {
		if v.Contains(addr) {
			return true
		}
	}

	return false
}

func (o *Options) V6Address() netip.Prefix {
	if len(o.Inet6Address) > 0 {
		return o.Inet6Address[0]
	}
	return netip.Prefix{}
}

func (o *Options) V6Contains(addr netip.Addr) bool {
	for _, v := range o.Inet6Address {
		if v.Contains(addr) {
			return true
		}
	}

	return false
}

type TunScheme struct {
	Scheme string
	Name   string
	Fd     int
}

func ParseTunScheme(str string) (TunScheme, error) {
	scheme, name, err := system.GetScheme(str)
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
