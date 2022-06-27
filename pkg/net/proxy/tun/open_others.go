//go:build !windows
// +build !windows

package tun

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func open(name string, mtu int) (_ stack.LinkEndpoint, err error) {
	if len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name too long: %s", name)
	}

	var fd int
	if strings.HasPrefix(name, "tun://") {
		fd, err = tun.Open(name[6:])
	} else if strings.HasPrefix(name, "fd://") {
		fd, err = strconv.Atoi(name[5:])
	} else {
		err = fmt.Errorf("invalid tun name: %s", name)
	}
	if err != nil {
		return nil, fmt.Errorf("open tun failed: %w", err)
	}

	return fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            uint32(mtu),
		EthernetHeader: false,
	})
}
