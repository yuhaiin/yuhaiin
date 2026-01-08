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
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func init() {
	register.RegisterProtocol(NewTun)
	relay.RegisterIgnoreNetOpErrString((&tcpip.ErrConnectionAborted{}).String())
	relay.RegisterIgnoreNetOpErrString((&tcpip.ErrAborted{}).String())
}

func NewTun(o *config.Tun, l netapi.Listener, handler netapi.Handler) (s netapi.Accepter, err error) {
	v4address, v4err := toPrefix(o.GetPortal(), true)
	v6address, v6err := toPrefix(o.GetPortalV6(), true)
	if v4err != nil && v6err != nil {
		return nil, errors.Join(v4err, v6err)
	}

	// fisrt for network address
	// last for broadcast address
	// others for host address
	// eg:
	//   172.19.0.1/24
	//   network address: 172.19.0.0
	//   broadcast address: 172.19.0.255
	//	 subnet: 172.19.0.1 - 172.19.0.254
	if v4address.Bits() >= 31 || v6address.Bits() >= 127 {
		return nil, fmt.Errorf("invalid address: ipv6: %v, ipv4: %v, the sub network must be smaller than ipv4(31) and ipv6(127)", o.GetPortal(), o.GetPortalV6())
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
			Platform: netlink.Platform{
				Darwin: netlink.Darwin{
					NetworkService: o.GetPlatform().GetDarwin().GetNetworkService(),
				},
			},
		},
		Handler: handler,
	}

	if v4address.IsValid() {
		opt.Inet4Address = []netip.Prefix{v4address}
	}

	if v6address.IsValid() && configuration.IPv6.Load() {
		opt.Inet6Address = []netip.Prefix{v6address}
	}

	if o.GetDriver() == config.Tun_system_gvisor {
		return tun2socket.New(opt)
	} else {
		return gvisor.New(opt)
	}
}

func toRoutes(r *config.Route) []netip.Prefix {
	if r == nil {
		return nil
	}

	var x []netip.Prefix
	add := func(s string) {
		prefix, err := toPrefix(s, false)
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

func toPrefix(str string, gateway bool) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(str)
	if err == nil {
		return prefix, nil
	}

	address, er := netip.ParseAddr(str)
	if er == nil {
		if !gateway {
			return netip.PrefixFrom(address, address.BitLen()), nil
		}

		if address.Is4() {
			return netip.PrefixFrom(address, 24), nil
		} else {
			return netip.PrefixFrom(address, 64), nil
		}
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
	switch runtime.GOOS {
	case "windows":
		tunPrefix = "wintun"
	case "darwin":
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
