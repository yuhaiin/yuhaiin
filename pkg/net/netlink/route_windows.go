package netlink

import (
	"errors"
	"log/slog"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func Route(opt *Options) (func(), error) {
	if opt.Interface.Scheme != "tun" {
		return nil, nil
	}
	if opt.Device == nil && opt.Endpoint != nil {
		if w, ok := opt.Endpoint.(interface{ Writer() Tun }); ok {
			opt.Device = w.Writer()
		}
	}

	luid := winipcfg.LUID(opt.Device.(WindowsTun).LUID())

	V4Address := opt.V4Address()
	if V4Address.IsValid() {
		if err := setAddress(luid, winipcfg.AddressFamily(windows.AF_INET), V4Address, opt.MTU); err != nil {
			log.Error("set ipv4 address failed", slog.Any("err", err))
		}
	}

	v6Address := opt.V6Address()
	if v6Address.IsValid() {
		if err := setAddress(luid, winipcfg.AddressFamily(windows.AF_INET6), v6Address, opt.MTU); err != nil {
			log.Error("set ipv6 address failed", slog.Any("err", err))
		}
	}

	return installRoutes(opt, &windowsRouteBackend{luid: luid, v4: V4Address.Addr(), v6: v6Address.Addr()})
}

type windowsRouteBackend struct {
	luid   winipcfg.LUID
	v4, v6 netip.Addr
}

func (b *windowsRouteBackend) gateway(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		return b.v4
	}
	return b.v6
}
func (b *windowsRouteBackend) Add(p netip.Prefix) (bool, error) {
	err := b.luid.AddRoute(p, b.gateway(p), 1)
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		if _, queryErr := b.luid.Route(p, b.gateway(p)); queryErr == nil {
			return false, nil
		}
	}
	return err == nil, err
}
func (b *windowsRouteBackend) Delete(p netip.Prefix) error {
	err := b.luid.DeleteRoute(p, b.gateway(p))
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil
	}
	return err
}
func (b *windowsRouteBackend) Close(_ bool) error { return nil }

func setAddress(luid winipcfg.LUID, family winipcfg.AddressFamily, address netip.Prefix, mtu int) error {
	err := luid.SetIPAddressesForFamily(family, []netip.Prefix{address})
	if err != nil {
		return err
	}

	err = luid.SetDNS(family, []netip.Addr{address.Addr().Next()}, nil)
	if err != nil {
		return err
	}

	inetIf, err := luid.IPInterface(family)
	if err != nil {
		return err
	}

	err = setInetIf(inetIf, mtu)
	if err != nil {
		return err
	}
	return nil
}

func setInetIf(inetIf *winipcfg.MibIPInterfaceRow, mtu int) error {
	inetIf.ForwardingEnabled = true
	inetIf.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	inetIf.DadTransmits = 0
	inetIf.ManagedAddressConfigurationSupported = false
	inetIf.OtherStatefulConfigurationSupported = false
	inetIf.NLMTU = uint32(mtu)
	inetIf.UseAutomaticMetric = false
	inetIf.Metric = 0
	return inetIf.Set()
}
