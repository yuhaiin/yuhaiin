//go:build (linux && amd64) || (linux && arm64)
// +build linux,amd64 linux,arm64

package tun

import (
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func init() {
	openFD = func(fd, mtu int) (stack.LinkEndpoint, error) {
		return fdbased.New(&fdbased.Options{
			FDs:            []int{fd},
			MTU:            uint32(mtu),
			EthernetHeader: false,
		})
	}
}
