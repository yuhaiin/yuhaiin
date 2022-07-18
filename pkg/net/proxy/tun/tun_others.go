//go:build !android
// +build !android

package tun

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func addMessage(addr proxy.Address, id stack.TransportEndpointID, opt *TunOpt) {
}
