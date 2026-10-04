//go:build !android

//nolint:unused // Keep the TUN ioctl helper for platforms that still open TUN by file descriptor.
package netlink

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func Route(opt *Options) (func(), error) {
	if opt.Interface.Scheme != "tun" {
		return nil, nil
	}

	link, err := netlink.LinkByName(opt.Interface.Name)
	if err != nil {
		return nil, err
	}

	err = netlink.LinkSetMTU(link, opt.MTU)
	if err != nil {
		return nil, fmt.Errorf("unable to set MTU: %w", err)
	}

	for _, address := range append(opt.Inet4Address, opt.Inet6Address...) {
		addr, err := netlink.ParseAddr(address.String())
		if err != nil {
			continue
		}

		err = netlink.AddrAdd(link, addr)
		if err != nil {
			return nil, fmt.Errorf("unable to add address: %w", err)
		}
	}

	if err = netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("unable to set link up: %w", err)
	}

	return installRoutes(opt, &linuxRouteBackend{linkIndex: link.Attrs().Index, rules: make(map[int]bool)})
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

func SetNoqueue(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %v", iface, err)
	}

	qdisc := &netlink.GenericQdisc{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0, 0),
		Parent:    netlink.HANDLE_ROOT,
		QdiscType: "noqueue",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("failed to add noqueue QDisc: %v", err)
	}

	return nil
}
