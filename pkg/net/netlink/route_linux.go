//go:build !android
// +build !android

package netlink

import (
	"fmt"
	"math/rand/v2"
	"net"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func Route(opt *Options) error {
	if opt.Interface.Scheme != "tun" {
		return nil
	}

	link, err := netlink.LinkByName(opt.Interface.Name)
	if err != nil {
		return err
	}

	err = netlink.LinkSetMTU(link, opt.MTU)
	if err != nil {
		return err
	}

	for _, address := range append(opt.Inet4Address, opt.Inet6Address...) {
		addr, err := netlink.ParseAddr(address.String())
		if err != nil {
			continue
		}

		err = netlink.AddrAdd(link, addr)
		if err != nil {
			return err
		}
	}

	if err = netlink.LinkSetUp(link); err != nil {
		return err
	}

	tableIndex := rand.Uint32()

	for _, route := range opt.Routes {
		r := netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst: &net.IPNet{
				IP:   route.Addr().AsSlice(),
				Mask: net.CIDRMask(route.Bits(), route.Addr().BitLen()),
			},
			Table: int(tableIndex),
		}
		err = netlink.RouteAdd(&r)
		if err != nil {
			return err
		}
	}

	// for _, address := range append(opt.Inet4Address, opt.Inet6Address...) {
	// 	it := netlink.NewRule()
	// 	it.Priority = 30001
	// 	it.Dst = &net.IPNet{
	// 		IP:   address.Addr().AsSlice(),
	// 		Mask: net.CIDRMask(address.Bits(), address.Addr().BitLen()),
	// 	}
	// 	it.Table = int(tableIndex)
	// 	it.Family = unix.AF_INET
	// 	err = netlink.RuleAdd(it)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	// it := netlink.NewRule()
	// it.Priority = 30001
	// it.Invert = true
	// it.Dport = netlink.NewRulePortRange(53, 53)
	// it.Table = unix.RT_TABLE_MAIN
	// it.SuppressPrefixlen = 0
	// it.Family = unix.AF_INET
	// err = netlink.RuleAdd(it)
	// if err != nil {
	// 	return err
	// }

	if len(opt.Routes) > 0 {
		if len(opt.Inet4Address) > 0 {
			it := netlink.NewRule()
			it.Priority = 30001
			it.Table = int(tableIndex)
			it.Family = unix.AF_INET
			err = netlink.RuleAdd(it)
			if err != nil {
				return err
			}
		}

		if len(opt.Inet6Address) > 0 {
			it := netlink.NewRule()
			it.Priority = 30001
			it.Table = int(tableIndex)
			it.Family = unix.AF_INET6
			err = netlink.RuleAdd(it)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

const ifReqSize = unix.IFNAMSIZ + 64

func getTunnelName(fd int32) (string, error) {
	var ifr [ifReqSize]byte
	var errno syscall.Errno
	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNGETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return "", fmt.Errorf("failed to get name of TUN device: %w", errno)
	}
	return unix.ByteSliceToString(ifr[:]), nil
}
