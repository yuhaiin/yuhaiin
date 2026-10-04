package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func init() {
	relay.RegisterIgnoreNetOpErrString((&tcpip.ErrConnectionAborted{}).String())
	relay.RegisterIgnoreNetOpErrString((&tcpip.ErrAborted{}).String())
}

func NewTun(o device.TunConfig, l netapi.Listener, handler netapi.Handler) (s netapi.Accepter, err error) {
	v4address, v4err := toPrefix(o.Portal, true)
	v6address, v6err := toPrefix(o.PortalV6, true)
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
		return nil, fmt.Errorf("invalid address: ipv6: %v, ipv4: %v, the sub network must be smaller than ipv4(31) and ipv6(127)", o.Portal, o.PortalV6)
	}

	sc, err := netlink.ParseTunScheme(o.Name)
	if err != nil {
		return nil, err
	}

	if o.AutoFakeIPRoute && sc.Scheme == "tun" && (!o.FakeIPRanges[0].IsValid() || !o.FakeIPRanges[1].IsValid()) {
		return nil, errors.New("automatic TUN routes require active FakeIP pools")
	}
	sc.Name = checkTunName(sc)

	opt := &device.Opt{
		Tun: o,
		Options: &netlink.Options{
			Interface: sc,
			MTU:       int(o.MTU),
			Platform: netlink.Platform{
				Darwin: netlink.Darwin{
					NetworkService: o.Platform.Darwin.NetworkService,
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

	userRoutes := toRoutes(o.Routes)
	opt.Routes = effectiveRoutes(opt.Options, userRoutes, o.AutoFakeIPRoute, o.FakeIPRanges)
	if o.Driver == device.DriverSystemGvisor {
		s, err = tun2socket.New(opt)
	} else {
		s, err = gvisor.New(opt)
	}
	if err != nil {
		return nil, err
	}
	return &routeAccepter{Accepter: s, options: opt.Options, userRoutes: userRoutes, autoFakeIP: o.AutoFakeIPRoute}, nil
}

func effectiveRoutes(options *netlink.Options, userRoutes []netip.Prefix, automatic bool, ranges [2]netip.Prefix) []netip.Prefix {
	routes := slices.Clone(userRoutes)
	if automatic {
		for _, p := range options.RoutesForFamilies(ranges[:]) {
			if p.Addr().Is6() && !configuration.IPv6.Load() {
				continue
			}
			routes = append(routes, p)
		}
	}
	return netlink.NormalizeRoutes(routes)
}

// routeAccepter keeps system route updates and Close mutually exclusive for
// both TUN drivers. Its userRoutes never include automatically added prefixes.
type routeAccepter struct {
	netapi.Accepter
	mu         sync.Mutex
	options    *netlink.Options
	userRoutes []netip.Prefix
	autoFakeIP bool
	closed     bool
}

func (t *routeAccepter) UpdateFakeIPRanges(ranges [2]netip.Prefix) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !t.autoFakeIP || t.options.RouteManager == nil {
		return nil
	}
	routes := effectiveRoutes(t.options, t.userRoutes, true, ranges)
	return t.options.RouteManager.Update(t.options.RoutesForFamilies(routes))
}

func (t *routeAccepter) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	var err error
	// Clean up while the interface still exists, before either driver closes it.
	if t.options.RouteManager != nil {
		err = t.options.RouteManager.Close()
	}
	if t.closed {
		return err
	}
	t.closed = true
	return errors.Join(err, t.Accepter.Close())
}

func toRoutes(routes []string) []netip.Prefix {
	if routes == nil {
		return nil
	}

	var x []netip.Prefix
	add := func(s string) {
		prefix, err := toPrefix(s, false)
		if err == nil {
			x = append(x, prefix)
		}
	}

	for _, v := range routes {
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

	return netlink.NormalizeRoutes(x)
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
