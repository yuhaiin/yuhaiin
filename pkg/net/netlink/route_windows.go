package netlink

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	wun "github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func Route(opt *Options) error {
	var device wun.Device

	if opt.Writer == nil && opt.Endpoint != nil {
		if w, ok := opt.Endpoint.(interface{ Writer() Tun }); ok {
			opt.Writer = w.Writer()
		}
	}

	if opt.Writer != nil {
		device = opt.Writer.Tun()
	}

	tt, ok := device.(*wun.NativeTun)
	if !ok {
		return fmt.Errorf("not a native tun device")
	}

	luid := winipcfg.LUID(tt.LUID())

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

	var err error
	for _, v := range opt.Routes {
		if v.Addr().Is4() && opt.V4Address().IsValid() {
			err = luid.AddRoute(v, V4Address.Addr(), 1)
		} else if opt.V6Address().IsValid() {
			err = luid.AddRoute(v, v6Address.Addr(), 1)
		}
		if err != nil {
			log.Error("add route failed", slog.Any("err", err))
		}
	}

	return nil
}

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
