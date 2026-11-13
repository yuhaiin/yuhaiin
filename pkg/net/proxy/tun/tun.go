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

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweighttun"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func NewTun(o device.TunConfig, l netapi.Listener, handler netapi.Handler) (s netapi.Accepter, err error) {
	if o.Stack != "" && o.Stack != "lightweight" {
		return nil, fmt.Errorf("unknown TUN stack %q", o.Stack)
	}
	// Migrate historical TUN stack and driver selections to lightweight.
	o.Stack = "lightweight"
	o.Driver = device.DriverChannel
	if err := lightweighttun.Validate(o); err != nil {
		return nil, err
	}
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

	s, err = lightweighttun.New(opt)
	if err != nil {
		return nil, err
	}
	return &tunAccepter{Accepter: s, options: opt.Options}, nil
}

// Link describes a running kernel TUN for the System Network Manager, which
// owns every route towards it. Index is zero for externally supplied fd://
// devices, whose routes are managed by their host.
type Link struct {
	Name           string
	Index          int
	IPv4, IPv6     netip.Prefix
	RequiredRoutes []netip.Prefix
}

// tunAccepter exposes the device's link next to the stack. The TUN itself
// never installs destination routes.
type tunAccepter struct {
	netapi.Accepter
	options *netlink.Options
}

func (t *tunAccepter) TunLink() Link {
	return Link{Name: t.options.Interface.Name, Index: t.options.Index, IPv4: t.options.V4Address(), IPv6: t.options.V6Address(),
		RequiredRoutes: slices.Clone(t.options.RequiredRoutes)}
}

// StackDiagnostic forwards the optional lightweight statistics. The
// underlying stack is sampled only on request.
func (t *tunAccepter) StackDiagnostic(limit int) lightweight.StackDiagnostics {
	if reporter, ok := t.Accepter.(interface {
		StackDiagnostic(int) lightweight.StackDiagnostics
	}); ok {
		return reporter.StackDiagnostic(limit)
	}
	return lightweight.StackDiagnostics{}
}

func (t *tunAccepter) TrafficControlQueue() (trafficcontrol.FairStats, bool) {
	if reporter, ok := t.Accepter.(trafficcontrol.QueueReporter); ok {
		return reporter.TrafficControlQueue()
	}
	return trafficcontrol.FairStats{}, false
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
