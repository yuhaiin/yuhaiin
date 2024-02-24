package tun

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	wun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func SetAddress(opt Opt) error {
	tt, ok := opt.Device.(*wun.NativeTun)
	if !ok {
		return fmt.Errorf("not a native tun device")
	}

	luid := winipcfg.LUID(tt.LUID())

	if opt.Portal.IsValid() {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET), []netip.Prefix{
			netip.PrefixFrom(opt.Portal, 24),
		})
		if err != nil {
			return err
		}

		err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), []netip.Addr{opt.Gateway}, nil)
		if err != nil {
			return err
		}

		err = luid.AddRoute(netip.PrefixFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 0), opt.Portal, 1)
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
			netip.PrefixFrom(opt.PortalV6, 64),
		})
		if err != nil {
			return err
		}

		err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET6), []netip.Addr{opt.GatewayV6}, nil)
		if err != nil {
			return err
		}

		err = luid.AddRoute(netip.PrefixFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), 0), opt.PortalV6, 1)
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
	Preload = SetAddress
}
