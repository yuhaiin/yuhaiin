package tun

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	wun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func route(opt Opt) error {
	tt, ok := opt.Device.(*wun.NativeTun)
	if !ok {
		return fmt.Errorf("not a native tun device")
	}

	luid := winipcfg.LUID(tt.LUID())

	if opt.Portal.IsValid() {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET), []netip.Prefix{
			opt.Portal,
		})
		if err != nil {
			return err
		}

		err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), []netip.Addr{opt.Portal.Addr().Next()}, nil)
		if err != nil {
			return err
		}

		err = luid.AddRoute(netip.PrefixFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 0), opt.Portal.Addr(), 1)
		if err != nil {
			return err
		}

		inetIf, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET))
		if err != nil {
			return err
		}

		inetIf.ForwardingEnabled = true
		inetIf.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inetIf.DadTransmits = 0
		inetIf.ManagedAddressConfigurationSupported = false
		inetIf.OtherStatefulConfigurationSupported = false
		inetIf.NLMTU = uint32(opt.Mtu)
		inetIf.UseAutomaticMetric = false
		inetIf.Metric = 0
		err = inetIf.Set()
		if err != nil {
			return err
		}
	}

	if opt.PortalV6.IsValid() {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET6), []netip.Prefix{
			opt.PortalV6,
		})
		if err != nil {
			return err
		}

		err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET6), []netip.Addr{opt.PortalV6.Addr().Next()}, nil)
		if err != nil {
			return err
		}

		err = luid.AddRoute(netip.PrefixFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), 0), opt.PortalV6.Addr(), 1)
		if err != nil {
			return err
		}

		inetIf, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET6))
		if err != nil {
			return err
		}

		inetIf.ForwardingEnabled = true
		inetIf.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inetIf.DadTransmits = 0
		inetIf.ManagedAddressConfigurationSupported = false
		inetIf.OtherStatefulConfigurationSupported = false
		inetIf.NLMTU = uint32(opt.Mtu)
		inetIf.UseAutomaticMetric = false
		inetIf.Metric = 0
		err = inetIf.Set()
		if err != nil {
			return err
		}
	}

	return nil
}

func init() {
	Route = route
}
