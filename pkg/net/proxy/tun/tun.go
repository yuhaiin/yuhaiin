package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
)

func init() {
	register.RegisterProtocol(NewTun)
}

func NewTun(o *listener.Tun, l netapi.Listener, handler netapi.Handler) (s netapi.Accepter, err error) {
	v4address, v4err := toPrefix(o.GetPortal())
	v6address, v6err := toPrefix(o.GetPortalV6())
	if v4err != nil && v6err != nil {
		return nil, errors.Join(v4err, v6err)
	}

	sc, err := netlink.ParseTunScheme(o.GetName())
	if err != nil {
		return nil, err
	}

	sc.Name = checkTunName(sc)

	opt := &device.Opt{
		Tun: o,
		Options: &netlink.Options{
			Interface: sc,
			MTU:       int(o.GetMtu()),
			Routes:    toRoutes(o.GetRoute()),
		},
		Handler: handler,
	}

	if v4address.IsValid() {
		opt.Inet4Address = []netip.Prefix{v4address}
	}

	if v6address.IsValid() && configuration.IPv6.Load() {
		opt.Inet6Address = []netip.Prefix{v6address}
	}

	if o.GetDriver() == listener.Tun_system_gvisor {
		return tun2socket.New(opt)
	} else {
		return gvisor.New(opt)
	}
}

func toRoutes(r *listener.Route) []netip.Prefix {
	if r == nil {
		return nil
	}

	var x []netip.Prefix
	add := func(s string) {
		prefix, err := toPrefix(s)
		if err == nil {
			x = append(x, prefix)
		}
	}

	for _, v := range r.GetRoutes() {
		switch {
		case strings.HasPrefix(v, "file:"):
			if remain := strings.TrimPrefix(v, "file:"); remain != "" {
				for v := range slice.RangeFileByLine(remain) {
					add(v)
				}
			}
		default:
			add(v)
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

func checkTunName(sc netlink.TunScheme) string {
	if sc.Scheme != "tun" {
		return sc.Name
	}

	ifces, err := net.Interfaces()
	if err != nil {
		return sc.Name
	}

	tunPrefix := "tun"
	if runtime.GOOS == "windows" {
		tunPrefix = "wintun"
	} else if runtime.GOOS == "darwin" {
		tunPrefix = "utun"

		if !strings.HasPrefix(sc.Name, tunPrefix) {
			sc.Name = "utun0"
		}
	}

	maxInt := -1
	exist := false
	for _, i := range ifces {
		if i.Name == sc.Name {
			exist = true
		}

		if !strings.HasPrefix(i.Name, tunPrefix) {
			continue
		}

		n, err := strconv.Atoi(strings.TrimPrefix(i.Name, tunPrefix))
		if err != nil {
			continue
		}
		if n > maxInt {
			maxInt = n
		}
	}

	if exist {
		sc.Name = fmt.Sprintf("%s%d", tunPrefix, maxInt+1)
	}
	return sc.Name
}
