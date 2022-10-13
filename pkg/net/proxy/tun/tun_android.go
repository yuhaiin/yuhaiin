package tun

import (
	"fmt"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func addMessage(addr proxy.Address, id stack.TransportEndpointID, opt *listener.Opts[*listener.Protocol_Tun]) {
	addPackageName(addr, opt.UidDumper, id.RemoteAddress.String(), int32(id.RemotePort))
}

func addPackageName(addr proxy.Address, dumper listener.UidDumper, srcAddr string, srcPort int32) {
	if dumper == nil {
		return
	}

	var network int32
	switch addr.Network() {
	case "tcp":
		network = syscall.IPPROTO_TCP
	case "udp":
		network = syscall.IPPROTO_UDP
	}

	uid, err := dumper.DumpUid(network, srcAddr, srcPort, addr.Hostname(), int32(addr.Port().Port()))
	if err != nil {
		log.Errorf("dump uid error: %v", err)
	}

	var name string
	if uid != 0 {
		name, err = dumper.GetUidInfo(uid)
		if err != nil {
			log.Errorf("get uid info error: %v", err)
		}
	}

	addr.WithValue(PACKAGE_MARK_KEY{}, fmt.Sprintf("%s(%d)", name, uid))
}
