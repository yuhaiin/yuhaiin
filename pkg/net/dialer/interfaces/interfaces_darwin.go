package interfaces

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func defaultRoute() (d DefaultRouteDetails, err error) {
	// We cannot rely on the delegated interface data on darwin. The NetworkExtension framework
	// seems to set the delegate interface only once, upon the *creation* of the VPN tunnel.
	// If a network transition (e.g. from Wi-Fi to Cellular) happens while the tunnel is
	// connected, it will be ignored and we will still try to set Wi-Fi as the default route
	// because the delegated interface is not updated by the NetworkExtension framework.
	//
	// We work around this on the Swift side with a NWPathMonitor instance that observes
	// the interface name of the first currently satisfied network path. Our Swift code will
	// call into `UpdateLastKnownDefaultRouteInterface`, so we can rely on that when it is set.
	//
	// If for any reason the Swift machinery didn't work and we don't get any updates, we will
	// fallback to the BSD logic.

	// Start by getting all available interfaces.
	// interfaces, err := net.Interfaces()
	// if err != nil {
	// 	return d, err
	// }
	// if err != nil {
	// 	log.Printf("defaultroute_darwin: could not get interfaces: %v", err)
	// 	return d, errors.New("ErrNoGatewayIndexFound")
	// }

	// getInterfaceByName := func(name string) *net.Interface {
	// 	for _, ifc := range interfaces {
	// 		if ifc.Name != name {
	// 			continue
	// 		}

	// 		if ifc.Flags&net.FlagUp != 0 {
	// 			log.Printf("defaultroute_darwin: %s is down", name)
	// 			return nil
	// 		}

	// 		addrs, _ := ifc.Addrs()
	// 		if len(addrs) == 0 {
	// 			log.Printf("defaultroute_darwin: %s has no addresses", name)
	// 			return nil
	// 		}
	// 		return &ifc
	// 	}
	// 	return nil
	// }

	// Did Swift set lastKnownDefaultRouteInterface? If so, we should use it and don't bother
	// with anything else. However, for sanity, do check whether Swift gave us with an interface
	// that exists, is up, and has an address.
	// if swiftIfName := lastKnownDefaultRouteIfName.Load(); swiftIfName != "" {
	// 	ifc := getInterfaceByName(swiftIfName)
	// 	if ifc != nil {
	// 		d.InterfaceName = ifc.Name
	// 		d.InterfaceIndex = ifc.Index
	// 		return d, nil
	// 	}
	// }

	// Fallback to the BSD logic
	idx, err := DefaultRouteInterfaceIndex()
	if err != nil {
		return d, err
	}
	iface, err := net.InterfaceByIndex(idx)
	if err != nil {
		return d, err
	}
	d.InterfaceName = iface.Name
	d.InterfaceIndex = idx
	return d, nil
}

// ErrNoGatewayIndexFound is returned by DefaultRouteInterfaceIndex when no
// default route is found.
var ErrNoGatewayIndexFound = errors.New("no gateway index found")

// DefaultRouteInterfaceIndex returns the index of the network interface that
// owns the default route. It returns the first IPv4 or IPv6 default route it
// finds (it does not prefer one or the other).
func DefaultRouteInterfaceIndex() (int, error) {
	// $ netstat -nr
	// Routing tables
	// Internet:
	// Destination        Gateway            Flags        Netif Expire
	// default            10.0.0.1           UGSc           en0         <-- want this one
	// default            10.0.0.1           UGScI          en1

	// From man netstat:
	// U       RTF_UP           Route usable
	// G       RTF_GATEWAY      Destination requires forwarding by intermediary
	// S       RTF_STATIC       Manually added
	// c       RTF_PRCLONING    Protocol-specified generate new routes on use
	// I       RTF_IFSCOPE      Route is associated with an interface scope

	rib, err := fetchRoutingTable()
	if err != nil {
		return 0, fmt.Errorf("route.FetchRIB: %w", err)
	}
	msgs, err := parseRoutingTable(rib)
	if err != nil {
		return 0, fmt.Errorf("route.ParseRIB: %w", err)
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		if isDefaultGateway(rm) {
			if delegatedIndex, err := getDelegatedInterface(rm.Index); err == nil && delegatedIndex != 0 {
				return delegatedIndex, nil
			} else if err != nil {
				log.Printf("interfaces_bsd: could not get delegated interface: %v", err)
			}
			return rm.Index, nil
		}
	}
	return 0, ErrNoGatewayIndexFound
}

var v4default = [4]byte{0, 0, 0, 0}
var v6default = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func isDefaultGateway(rm *route.RouteMessage) bool {
	if rm.Flags&unix.RTF_GATEWAY == 0 {
		return false
	}
	// Defined locally because FreeBSD does not have unix.RTF_IFSCOPE.
	const RTF_IFSCOPE = 0x1000000
	if rm.Flags&RTF_IFSCOPE != 0 {
		return false
	}

	// Addrs is [RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK, ...]
	if len(rm.Addrs) <= unix.RTAX_NETMASK {
		return false
	}

	dst := rm.Addrs[unix.RTAX_DST]
	netmask := rm.Addrs[unix.RTAX_NETMASK]
	if dst == nil || netmask == nil {
		return false
	}

	if dst.Family() == syscall.AF_INET && netmask.Family() == syscall.AF_INET {
		dstAddr, dstOk := dst.(*route.Inet4Addr)
		nmAddr, nmOk := netmask.(*route.Inet4Addr)
		if dstOk && nmOk && dstAddr.IP == v4default && nmAddr.IP == v4default {
			return true
		}
	}

	if dst.Family() == syscall.AF_INET6 && netmask.Family() == syscall.AF_INET6 {
		dstAddr, dstOk := dst.(*route.Inet6Addr)
		nmAddr, nmOk := netmask.(*route.Inet6Addr)
		if dstOk && nmOk && dstAddr.IP == v6default && nmAddr.IP == v6default {
			return true
		}
	}

	return false
}

// fetchRoutingTable calls route.FetchRIB, fetching NET_RT_DUMP2.
func fetchRoutingTable() (rib []byte, err error) {
	return route.FetchRIB(syscall.AF_UNSPEC, syscall.NET_RT_DUMP2, 0)
}

func parseRoutingTable(rib []byte) ([]route.Message, error) {
	return route.ParseRIB(syscall.NET_RT_IFLIST2, rib)
}

var ifNames struct {
	sync.Mutex
	m map[int]string // ifindex => name
}

// getDelegatedInterface returns the interface index of the underlying interface
// for the given interface index. 0 is returned if the interface does not
// delegate.
func getDelegatedInterface(ifIndex int) (int, error) {
	ifNames.Lock()
	defer ifNames.Unlock()

	// To get the delegated interface, we do what ifconfig does and use the
	// SIOCGIFDELEGATE ioctl. It operates in term of a ifreq struct, which
	// has to be populated with a interface name. To avoid having to do a
	// interface index -> name lookup every time, we cache interface names
	// (since indexes and names are stable after boot).
	ifName, ok := ifNames.m[ifIndex]
	if !ok {
		iface, err := net.InterfaceByIndex(ifIndex)
		if err != nil {
			return 0, err
		}
		ifName = iface.Name
		Set(&ifNames.m, ifIndex, ifName)
	}

	// Only tunnels (like Tailscale itself) have a delegated interface, avoid
	// the ioctl if we can.
	if !strings.HasPrefix(ifName, "utun") {
		return 0, nil
	}

	// We don't cache the result of the ioctl, since the delegated interface can
	// change, e.g. if the user changes the preferred service order in the
	// network preference pane.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	// Match the ifreq struct/union from the bsd/net/if.h header in the Darwin
	// open source release.
	var ifr struct {
		ifr_name      [unix.IFNAMSIZ]byte
		ifr_delegated uint32
	}
	copy(ifr.ifr_name[:], ifName)

	// SIOCGIFDELEGATE is not in the Go x/sys package or in the public macOS
	// <sys/sockio.h> headers. However, it is in the Darwin/xnu open source
	// release (and is used by ifconfig, see
	// https://github.com/apple-oss-distributions/network_cmds/blob/6ccdc225ad5aa0d23ea5e7d374956245d2462427/ifconfig.tproj/ifconfig.c#L2183-L2187).
	// We generate its value by evaluating the `_IOWR('i', 157, struct ifreq)`
	// macro, which is how it's defined in
	// https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/sys/sockio.h#L264
	const SIOCGIFDELEGATE = 0xc020699d

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(SIOCGIFDELEGATE),
		uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return 0, errno
	}
	return int(ifr.ifr_delegated), nil
}

// Set populates an entry in a map, making the map if necessary.
//
// That is, it assigns (*m)[k] = v, making *m if it was nil.
func Set[K comparable, V any, T ~map[K]V](m *T, k K, v V) {
	if *m == nil {
		*m = make(map[K]V)
	}
	(*m)[k] = v
}
