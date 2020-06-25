package process

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/process/controller"

	"github.com/Asutorufa/yuhaiin/config"
)

var (
	ConFig         *config.Setting
	LocalListenCon *controller.LocalListen
	MatchCon       *controller.MatchController
)

func SetConFig(config *config.Setting, first bool) (erra error) {
	if first {
		MatchCon = controller.NewMatchController(config.BypassFile)
		LocalListenCon = controller.NewLocalListenController()
	}

	if ConFig.DnsServer != config.DnsServer || ConFig.IsDNSOverHTTPS != config.IsDNSOverHTTPS || first {
		MatchCon.SetDNS(config.DnsServer, config.IsDNSOverHTTPS)
	}

	if ConFig.DnsSubNet != config.DnsSubNet || first {
		_, subnet, err := net.ParseCIDR(config.DnsSubNet)
		if err != nil {
			if net.ParseIP(config.DnsSubNet).To4() != nil {
				_, subnet, _ = net.ParseCIDR(config.DnsSubNet + "/32")
			}

			if net.ParseIP(config.DnsSubNet).To16() != nil {
				_, subnet, _ = net.ParseCIDR(config.DnsSubNet + "/128")
			}
		}
		MatchCon.SetDNSSubNet(subnet)
	}

	if ConFig.DNSAcrossProxy != config.DNSAcrossProxy || first {
		MatchCon.EnableDNSProxy(config.DNSAcrossProxy)
	}

	if ConFig.Bypass != config.Bypass || first {
		MatchCon.EnableBYPASS(config.Bypass)
	}

	if ConFig.BypassFile != config.BypassFile || first {
		err := MatchCon.SetBypass(config.BypassFile)
		if err != nil {
			erra = fmt.Errorf("%v\nUpdateMatchErr -> %v", erra, err)
		}
	}

	if (ConFig.SsrPath != config.SsrPath && SsrCmd != nil) || first {
		controller.SSRPath = config.SsrPath
		err := ChangeNode()
		if err != nil {
			if !first {
				erra = fmt.Errorf("%v\nChangeNodeErr -> %v", erra, err)
			}
		}
	}

	if ConFig.HttpProxyAddress != config.HttpProxyAddress || first {
		err := LocalListenCon.SetHTTPHost(config.HttpProxyAddress)
		if err != nil {
			erra = fmt.Errorf("UpdateHTTPListenErr -> %v", err)
		}
	}
	if ConFig.Socks5ProxyAddress != config.Socks5ProxyAddress || first {
		err := LocalListenCon.SetSocks5Host(config.Socks5ProxyAddress)
		if err != nil {
			erra = fmt.Errorf("UpdateSOCKS5ListenErr -> %v", err)
		}
	}

	if ConFig.RedirProxyAddress != config.RedirProxyAddress || first {
		err := LocalListenCon.SetRedirHost(config.RedirProxyAddress)
		if err != nil {
			erra = fmt.Errorf("UpdateRedirListenErr -> %v", err)
		}
	}

	// others
	ConFig = config

	return
}

func ProcessInit() (erra error) {
	ConFig, _ = config.SettingDecodeJSON()
	return SetConFig(ConFig, true)
}
