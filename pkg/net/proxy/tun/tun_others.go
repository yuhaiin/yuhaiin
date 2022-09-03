//go:build !android
// +build !android

package tun

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func addMessage(addr proxy.Address, id stack.TransportEndpointID, opt *config.Opts[*config.ServerProtocol_Tun]) {
}
