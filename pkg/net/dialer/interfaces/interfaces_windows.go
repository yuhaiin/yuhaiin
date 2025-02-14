package interfaces

import (
	"log"
	"net/url"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/tsconst"
)

func notTailscaleInterface(iface *winipcfg.IPAdapterAddresses) bool {
	// TODO(bradfitz): do this without the Description method's
	// utf16-to-string allocation. But at least we only do it for
	// the virtual interfaces, for which there won't be many.
	if iface.IfType != winipcfg.IfTypePropVirtual {
		return true
	}
	desc := iface.Description()
	return !(strings.Contains(desc, tsconst.WintunInterfaceDesc) ||
		strings.Contains(desc, tsconst.WintunInterfaceDesc0_14)) ||
		strings.Contains(desc, "tun") ||
		strings.Contains(desc, "yuhaiin")
}

// getInterfaces returns a map of interfaces keyed by their LUID for
// all interfaces matching the provided match predicate.
//
// The family (AF_UNSPEC, AF_INET, or AF_INET6) and flags are passed
// to winipcfg.GetAdaptersAddresses.
func getInterfaces(family winipcfg.AddressFamily, flags winipcfg.GAAFlags, match func(*winipcfg.IPAdapterAddresses) bool) (map[winipcfg.LUID]*winipcfg.IPAdapterAddresses, error) {
	ifs, err := winipcfg.GetAdaptersAddresses(family, flags)
	if err != nil {
		return nil, err
	}
	ret := map[winipcfg.LUID]*winipcfg.IPAdapterAddresses{}
	for _, iface := range ifs {
		if match(iface) {
			ret[iface.LUID] = iface
		}
	}
	return ret, nil
}

// GetWindowsDefault returns the interface that has the non-Tailscale
// default route for the given address family.
//
// It returns (nil, nil) if no interface is found.
//
// The family must be one of AF_INET or AF_INET6.
func GetWindowsDefault(family winipcfg.AddressFamily) (*winipcfg.IPAdapterAddresses, error) {
	ifs, err := getInterfaces(family, winipcfg.GAAFlagIncludeAllInterfaces, func(iface *winipcfg.IPAdapterAddresses) bool {
		switch iface.IfType {
		case winipcfg.IfTypeSoftwareLoopback:
			return false
		}
		switch family {
		case windows.AF_INET:
			if iface.Flags&winipcfg.IPAAFlagIpv4Enabled == 0 {
				return false
			}
		case windows.AF_INET6:
			if iface.Flags&winipcfg.IPAAFlagIpv6Enabled == 0 {
				return false
			}
		}
		return iface.OperStatus == winipcfg.IfOperStatusUp && notTailscaleInterface(iface)
	})
	if err != nil {
		return nil, err
	}

	routes, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return nil, err
	}

	bestMetric := ^uint32(0)
	var bestIface *winipcfg.IPAdapterAddresses
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 {
			// Not a default route.
			continue
		}
		iface := ifs[route.InterfaceLUID]
		if iface == nil {
			continue
		}

		// Microsoft docs say:
		//
		// "The actual route metric used to compute the route
		// preferences for IPv4 is the summation of the route
		// metric offset specified in the Metric member of the
		// MIB_IPFORWARD_ROW2 structure and the interface
		// metric specified in this member for IPv4"
		metric := route.Metric
		switch family {
		case windows.AF_INET:
			metric += iface.Ipv4Metric
		case windows.AF_INET6:
			metric += iface.Ipv6Metric
		}
		if metric < bestMetric {
			bestMetric = metric
			bestIface = iface
		}
	}

	return bestIface, nil
}

func defaultRoute() (d DefaultRouteDetails, err error) {
	// We always return the IPv4 default route.
	// TODO(bradfitz): adjust API if/when anything cares. They could in theory differ, though,
	// in which case we might send traffic to the wrong interface.
	iface, err := GetWindowsDefault(windows.AF_INET)
	if err != nil {
		return d, err
	}
	if iface != nil {
		d.InterfaceName = iface.FriendlyName()
		d.InterfaceDesc = iface.Description()
		d.InterfaceIndex = int(iface.IfIndex)
	}
	return d, nil
}

var (
	winHTTP                  = windows.NewLazySystemDLL("winhttp.dll")
	detectAutoProxyConfigURL = winHTTP.NewProc("WinHttpDetectAutoProxyConfigUrl")

	kernel32   = windows.NewLazySystemDLL("kernel32.dll")
	globalFree = kernel32.NewProc("GlobalFree")
)

const (
	winHTTP_AUTO_DETECT_TYPE_DHCP  = 0x00000001
	winHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002
)

func getPACWindows() string {
	var res *uint16
	r, _, e := detectAutoProxyConfigURL.Call(
		winHTTP_AUTO_DETECT_TYPE_DHCP|winHTTP_AUTO_DETECT_TYPE_DNS_A,
		uintptr(unsafe.Pointer(&res)),
	)
	if r == 1 {
		if res == nil {
			log.Printf("getPACWindows: unexpected success with nil result")
			return ""
		}
		defer globalFree.Call(uintptr(unsafe.Pointer(res)))
		s := windows.UTF16PtrToString(res)
		s = strings.TrimSpace(s)
		if s == "" {
			return "" // Issue 2357: invalid URL "\n" from winhttp; ignoring
		}
		if _, err := url.Parse(s); err != nil {
			log.Printf("getPACWindows: invalid URL %q from winhttp; ignoring", s)
			return ""
		}
		return s
	}
	const (
		ERROR_WINHTTP_AUTODETECTION_FAILED = 12180
	)
	if e == syscall.Errno(ERROR_WINHTTP_AUTODETECTION_FAILED) {
		// Common case on networks without advertised PAC.
		return ""
	}
	log.Printf("getPACWindows: %T=%v", e, e) // syscall.Errno=0x....
	return ""
}
