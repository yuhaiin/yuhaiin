package netlink

import (
	"fmt"
	"io"
	"net/netip"

	"golang.org/x/sys/windows"
	wun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func Route(opt *Options) error {
	var device wun.Device

	if opt.Writer == nil && opt.Endpoint != nil {
		if w, ok := opt.Endpoint.(interface{ Writer() io.ReadWriteCloser }); ok {
			opt.Writer = w.Writer()
		}
	}

	if opt.Writer != nil {
		dev, ok := opt.Writer.(interface{ Device() wun.Device })
		if !ok {
			return fmt.Errorf("invalid device type")
		}
		device = dev.Device()
	}

	tt, ok := device.(*wun.NativeTun)
	if !ok {
		return fmt.Errorf("not a native tun device")
	}

	luid := winipcfg.LUID(tt.LUID())

	for _, v := range opt.Inet4Address {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET), []netip.Prefix{v})
		if err != nil {
			return err
		}

		err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), []netip.Addr{v.Addr().Next()}, nil)
		if err != nil {
			return err
		}

		err = luid.AddRoute(netip.PrefixFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 0), v.Addr(), 1)
		if err != nil {
			return err
		}

		inetIf, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET))
		if err != nil {
			return err
		}

		err = setInetIf(inetIf, opt.MTU)
		if err != nil {
			return err
		}
		break
	}

	for _, v := range opt.Inet6Address {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET6), []netip.Prefix{v})
		if err != nil {
			return err
		}

		err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET6), []netip.Addr{v.Addr().Next()}, nil)
		if err != nil {
			return err
		}

		err = luid.AddRoute(netip.PrefixFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), 0), v.Addr(), 1)
		if err != nil {
			return err
		}

		inetIf, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET6))
		if err != nil {
			return err
		}

		err = setInetIf(inetIf, opt.MTU)
		if err != nil {
			return err
		}
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
