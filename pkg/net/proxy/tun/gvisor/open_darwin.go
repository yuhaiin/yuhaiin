package tun

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func open(name string, driver listener.TunEndpointDriver, mtu int) (_ stack.LinkEndpoint, err error) {
	return nil, fmt.Errorf("open tun device failed: unsupported darwin")
}
