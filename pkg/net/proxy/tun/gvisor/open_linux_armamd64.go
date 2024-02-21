//go:build (linux && amd64) || (linux && arm64)
// +build linux,amd64 linux,arm64

package tun

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func openFD(fd, mtu int, driver listener.TunEndpointDriver) (stack.LinkEndpoint, error) {
	switch driver {
	case listener.Tun_channel:
		w, err := newFDWriter(fd)
		if err != nil {
			return nil, fmt.Errorf("create writev dispatcher failed: %w", err)
		}

		ce := NewEndpoint(w, uint32(mtu), "")

		return ce, nil
	default:
		return fdbased.New(&fdbased.Options{
			FDs:            []int{fd},
			MTU:            uint32(mtu),
			EthernetHeader: false,
		})
	}
}
