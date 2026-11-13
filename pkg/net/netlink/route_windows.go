package netlink

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// ConfigureTun sets the addresses, DNS and MTU of a Wintun adapter. It
// installs no destination routes: those belong to the System Network Manager.
func ConfigureTun(opt *Options) (func(), error) {
	if opt.Interface.Scheme != "tun" {
		return nil, nil
	}
	device, ok := opt.Device.(WindowsTun)
	if !ok {
		return nil, fmt.Errorf("windows TUN configuration requires an active WindowsTun, got %T", opt.Device)
	}
	luid := winipcfg.LUID(device.LUID())

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
	row, err := luid.Interface()
	if err != nil {
		return nil, fmt.Errorf("query TUN interface index: %w", err)
	}
	opt.Index = int(row.InterfaceIndex)
	return nil, nil
}

// windowsRouteBackend adds routes per interface LUID. Windows has no policy
// routing for these routes; prefixes are unique by construction and the
// longest-prefix match picks between them.
type windowsRouteBackend struct{}

func newPlatformRouteBackend() (routeBackend, error) { return windowsRouteBackend{}, nil }

func nextHop(r SystemRoute) netip.Addr {
	if r.Gateway.IsValid() {
		return r.Gateway
	}
	// On-link: point-to-point adapters (Wintun, WireGuard) need no gateway.
	if r.Prefix.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

func (windowsRouteBackend) Add(r SystemRoute) (bool, error) {
	luid, err := winipcfg.LUIDFromIndex(uint32(r.Link))
	if err != nil {
		return false, err
	}
	err = luid.AddRoute(r.Prefix, nextHop(r), 1)
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		if _, queryErr := luid.Route(r.Prefix, nextHop(r)); queryErr == nil {
			return false, nil
		}
		return false, fmt.Errorf("%w: %w", ErrRouteConflict, err)
	}
	return err == nil, err
}

func (windowsRouteBackend) Delete(r SystemRoute) error {
	luid, err := winipcfg.LUIDFromIndex(uint32(r.Link))
	if err != nil {
		// The interface is gone and its routes with it.
		return nil
	}
	err = luid.DeleteRoute(r.Prefix, nextHop(r))
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil
	}
	return err
}

func (windowsRouteBackend) Close() error { return nil }

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
