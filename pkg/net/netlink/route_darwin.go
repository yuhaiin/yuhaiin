package netlink

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const (
	SIOCAIFADDR_IN6       = 2155899162 // netinet6/in6_var.h
	IN6_IFF_NODAD         = 0x0020     // netinet6/in6_var.h
	IN6_IFF_SECURED       = 0x0400     // netinet6/in6_var.h
	ND6_INFINITE_LIFETIME = 0xFFFFFFFF // netinet6/nd6.h
)

type ifAliasReq struct {
	Name    [unix.IFNAMSIZ]byte
	Addr    unix.RawSockaddrInet4
	Dstaddr unix.RawSockaddrInet4
	Mask    unix.RawSockaddrInet4
}

type ifAliasReq6 struct {
	Name     [16]byte
	Addr     unix.RawSockaddrInet6
	Dstaddr  unix.RawSockaddrInet6
	Mask     unix.RawSockaddrInet6
	Flags    uint32
	Lifetime addrLifetime6
}

type addrLifetime6 struct {
	Expire    float64
	Preferred float64
	Vltime    uint32
	Pltime    uint32
}

func Route(options *Options) error {
	var iface string

	if options.Interface.Scheme == "tun" {
		iface = options.Interface.Name
	} else {
		return nil
		// name, err := unix.GetsockoptString(
		// 	int(options.Interface.Fd),
		// 	2, /* #define SYSPROTO_CONTROL 2 */
		// 	2, /* #define UTUN_OPT_IFNAME 2 */
		// )
		// if err != nil {
		// 	return fmt.Errorf("GetSockoptString: %w", err)
		// }
		// iface = name
	}

	if iface == "" {
		return fmt.Errorf("empty interface name")
	}

	if err := setMtu(iface, options.MTU); err != nil {
		return err
	}

	for _, address := range append(options.Inet4Address, options.Inet6Address...) {
		if err := setAddress(iface, address); err != nil {
			return err
		}
	}

	for _, route := range options.Routes {
		if route.Addr().Is4() {
			if len(options.Inet4Address) <= 0 {
				continue
			}
			if err := addRoute(route, options.V4Address().Addr()); err != nil {
				return err
			}
		} else {
			if len(options.Inet6Address) <= 0 {
				continue
			}
			if err := addRoute(route, options.V6Address().Addr()); err != nil {
				return err
			}
		}
	}

	return nil
}

func useSocket(domain, typ, proto int, block func(socketFd int) error) error {
	socketFd, err := unix.Socket(domain, typ, proto)
	if err != nil {
		return err
	}
	defer unix.Close(socketFd)
	return block(socketFd)
}

func addRoute(destination netip.Prefix, gateway netip.Addr) error {
	routeMessage := route.RouteMessage{
		Type:    unix.RTM_ADD,
		Flags:   unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY,
		Version: unix.RTM_VERSION,
		Seq:     1,
	}
	if gateway.Is4() {
		routeMessage.Addrs = []route.Addr{
			syscall.RTAX_DST:     &route.Inet4Addr{IP: destination.Addr().As4()},
			syscall.RTAX_NETMASK: &route.Inet4Addr{IP: netip.MustParseAddr(net.IP(net.CIDRMask(destination.Bits(), 32)).String()).As4()},
			syscall.RTAX_GATEWAY: &route.Inet4Addr{IP: gateway.As4()},
		}
	} else {
		routeMessage.Addrs = []route.Addr{
			syscall.RTAX_DST:     &route.Inet6Addr{IP: destination.Addr().As16()},
			syscall.RTAX_NETMASK: &route.Inet6Addr{IP: netip.MustParseAddr(net.IP(net.CIDRMask(destination.Bits(), 128)).String()).As16()},
			syscall.RTAX_GATEWAY: &route.Inet6Addr{IP: gateway.As16()},
		}
	}
	request, err := routeMessage.Marshal()
	if err != nil {
		return err
	}
	return useSocket(unix.AF_ROUTE, unix.SOCK_RAW, 0, func(socketFd int) error {
		_, err := unix.Write(socketFd, request)
		return err
	})
}

func setAddress(ifaceName string, address netip.Prefix) error {
	var req, socketAddr uintptr
	var afInt int

	if address.Addr().Is4() {
		ifReq := ifAliasReq{
			Addr: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   address.Addr().As4(),
			},
			Dstaddr: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   address.Addr().As4(),
			},
			Mask: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   netip.MustParseAddr(net.IP(net.CIDRMask(address.Bits(), 32)).String()).As4(),
			},
		}
		copy(ifReq.Name[:], ifaceName)

		afInt = unix.AF_INET
		req = uintptr(unsafe.Pointer(&ifReq))
		socketAddr = uintptr(unix.SIOCAIFADDR)
	} else {
		ifReq6 := ifAliasReq6{
			Addr: unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   address.Addr().As16(),
			},
			Mask: unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   netip.MustParseAddr(net.IP(net.CIDRMask(address.Bits(), 128)).String()).As16(),
			},
			Flags: IN6_IFF_NODAD | IN6_IFF_SECURED,
			Lifetime: addrLifetime6{
				Vltime: ND6_INFINITE_LIFETIME,
				Pltime: ND6_INFINITE_LIFETIME,
			},
		}
		if address.Bits() == 128 {
			ifReq6.Dstaddr = unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   address.Addr().Next().As16(),
			}
		}
		copy(ifReq6.Name[:], ifaceName)

		req = uintptr(unsafe.Pointer(&ifReq6))
		socketAddr = uintptr(SIOCAIFADDR_IN6)
		afInt = unix.AF_INET6
	}

	return useSocket(afInt, unix.SOCK_DGRAM, 0, func(socketFd int) error {
		if _, _, errno := unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(socketFd),
			socketAddr,
			req,
		); errno != 0 {
			return os.NewSyscallError("SIOCAIFADDR", errno)
		}
		return nil
	})
}

func setMtu(ifaceName string, mtu int) error {
	err := useSocket(unix.AF_INET, unix.SOCK_DGRAM, 0, func(socketFd int) error {
		var ifr unix.IfreqMTU
		copy(ifr.Name[:], ifaceName)
		ifr.MTU = int32(mtu)
		return unix.IoctlSetIfreqMTU(socketFd, &ifr)
	})
	if err != nil {
		return os.NewSyscallError("IoctlSetIfreqMTU", err)
	}

	return nil
}
