package tun

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	tun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

func init() {
	listener.RegisterProtocol(NewTun)
}

func NewTun(o *listener.Inbound_Tun) func(netapi.Listener) (s netapi.Accepter, err error) {
	return func(l netapi.Listener) (s netapi.Accepter, err error) {
		v4address, v4err := toPrefix(o.Tun.Portal)
		v6address, v6err := toPrefix(o.Tun.PortalV6)
		if v4err != nil && v6err != nil {
			return nil, errors.Join(v4err, v6err)
		}

		sc, err := netlink.ParseTunScheme(o.Tun.Name)
		if err != nil {
			return nil, err
		}

		opt := &tun.Opt{
			Inbound_Tun: o,
			Options: &netlink.Options{
				Interface: sc,
				MTU:       int(o.Tun.Mtu),
				Routes:    toRoutes(o.Tun.Route),
			},
		}

		if v4address.IsValid() {
			opt.Inet4Address = []netip.Prefix{v4address}
		}

		if v6address.IsValid() {
			opt.Inet6Address = []netip.Prefix{v6address}
		}

		if o.Tun.Driver == listener.Tun_system_gvisor {
			return tun2socket.New(opt)
		} else {
			return tun.New(opt)
		}
	}
}

func toRoutes(r *listener.Route) []netip.Prefix {
	if r == nil {
		return nil
	}

	var x []netip.Prefix
	for _, v := range r.Routes {
		prefix, err := toPrefix(v)
		if err == nil {
			x = append(x, prefix)
		}
	}

	return x
}

func toPrefix(str string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(str)
	if err == nil {
		return prefix, nil
	}

	address, er := netip.ParseAddr(str)
	if er == nil {
		return netip.PrefixFrom(address, address.BitLen()), nil
	}

	return netip.Prefix{}, fmt.Errorf("invalid IP address: %w", err)
}
