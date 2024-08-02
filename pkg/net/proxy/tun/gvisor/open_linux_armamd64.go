//go:build (linux && amd64) || (linux && arm64)
// +build linux,amd64 linux,arm64

// github.com/google/gvisor/pkg/tcpip/link/fdbased/mmap.go only support linux,amd64 linux,arm64
// so add build tag for fdbased
package tun

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	vnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	gun "gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func init() {
	openFD = func(sc netlink.TunScheme, mtu int) (stack.LinkEndpoint, error) {
		switch sc.Scheme {
		case "fd":
			return fdbased.New(&fdbased.Options{
				FDs:               []int{sc.Fd},
				MTU:               uint32(mtu),
				RXChecksumOffload: true,
			})
		case "tun":
			// fdbased current not support gso, so open new tun direct instead of wireguard
			//
			// https://github.com/google/gvisor/blob/ef1ca17e584230d9c70f31ac991549adede09839/pkg/tcpip/link/fdbased/endpoint.go#L323
			// check is socket, can't enable gso
			dev, err := gun.Open(sc.Name)
			if err != nil {
				return nil, fmt.Errorf("create tun failed: %w", err)
			}

			tunLink, err := vnetlink.LinkByName(sc.Name)
			if err != nil {
				unix.Close(dev)
				return nil, err
			}

			if err := vnetlink.LinkSetMTU(tunLink, mtu); err != nil {
				unix.Close(dev)
				return nil, err
			}

			return fdbased.New(&fdbased.Options{
				FDs:                   []int{dev},
				MTU:                   uint32(mtu),
				RXChecksumOffload:     true,
				MaxSyscallHeaderBytes: 0x00,
			})

		default:
			return nil, fmt.Errorf("invalid tun: %v", sc)
		}
	}
}
