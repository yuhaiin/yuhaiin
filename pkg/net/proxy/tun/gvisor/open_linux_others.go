//go:build linux && !((linux && amd64) || (linux && arm64))
// +build linux
// +build !linux !amd64
// +build !linux !arm64

package tun

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func openFD(fd, mtu int, driver listener.TunEndpointDriver) (stack.LinkEndpoint, error) {
	w, err := newFDWriter(fd)
	if err != nil {
		return nil, fmt.Errorf("create writev dispatcher failed: %w", err)
	}

	ce := NewEndpoint(w, uint32(mtu), "")
	return ce, nil
}
