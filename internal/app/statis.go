package app

import (
	"net"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

var _ proxy.Proxy = (*FlowStatis)(nil)

type FlowStatis struct {
	*connManager
}

func NewFlowStatis(c *config.Config, p proxy.Proxy) *FlowStatis {
	return &FlowStatis{connManager: newConnManager(NewBypassManager(c, p))}
}

func diffDNS(old, new *config.DNS) bool {
	if old.Host != new.Host {
		return true
	}
	if old.DOH != new.DOH {
		return true
	}
	if old.Subnet != new.Subnet {
		return true
	}
	return false
}

func getDNS(dc *config.DNS) dns.DNS {
	_, subnet, err := net.ParseCIDR(dc.Subnet)
	if err != nil {
		if net.ParseIP(dc.Subnet).To4() != nil {
			_, subnet, _ = net.ParseCIDR(dc.Subnet + "/32")
		}

		if net.ParseIP(dc.Subnet).To16() != nil {
			_, subnet, _ = net.ParseCIDR(dc.Subnet + "/128")
		}
	}
	if dc.DOH {
		return dns.NewDoH(dc.Host, subnet, nil)
	}
	return dns.NewDNS(dc.Host, subnet, nil)
}
