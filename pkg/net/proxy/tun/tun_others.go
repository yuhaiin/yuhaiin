//go:build !android
// +build !android

package tun

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func addMessage(addr proxy.Address, id stack.TransportEndpointID, opt *listener.Opts[*listener.Protocol_Tun]) {
}
