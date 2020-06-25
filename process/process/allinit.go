package process

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/process/controller"

	"github.com/Asutorufa/yuhaiin/net/common"

	"github.com/Asutorufa/yuhaiin/config"
)

var (
	ConFig         *config.Setting
	LocalListenCon *controller.LocalListen
	MatchCon       *controller.MatchController
)

func UpdateConFig() {
	ConFig, _ = config.SettingDecodeJSON()
}

func SetConFig(config *config.Setting) (erra error) {
	if ConFig.DnsServer != config.DnsServer || ConFig.IsDNSOverHTTPS != config.IsDNSOverHTTPS {
		MatchCon.SetDNS(config.DnsServer, config.IsDNSOverHTTPS)
	}

	if ConFig.DnsSubNet != config.DnsSubNet {
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

	if ConFig.DNSAcrossProxy != config.DNSAcrossProxy {
		if config.DNSAcrossProxy {
			MatchCon.EnableDNSProxy()
		} else {
			MatchCon.DisEnableDNSProxy()
		}
	}

	if ConFig.BypassFile != config.BypassFile {
		err := MatchCon.SetBypass(config.BypassFile)
		if err != nil {
			erra = fmt.Errorf("%v\nUpdateMatchErr -> %v", erra, err)
		}
	}

	if ConFig.HttpProxyAddress != config.HttpProxyAddress {
		err := LocalListenCon.SetHTTPHost(config.HttpProxyAddress)
		if err != nil {
			erra = fmt.Errorf("UpdateHTTPListenErr -> %v", err)
		}
	}
	if ConFig.Socks5ProxyAddress != config.Socks5ProxyAddress {
		err := LocalListenCon.SetSocks5Host(config.Socks5ProxyAddress)
		if err != nil {
			erra = fmt.Errorf("UpdateSOCKS5ListenErr -> %v", err)
		}
	}

	if ConFig.RedirProxyAddress != config.RedirProxyAddress {
		err := LocalListenCon.SetRedirHost(config.RedirProxyAddress)
		if err != nil {
			erra = fmt.Errorf("UpdateRedirListenErr -> %v", err)
		}
	}

	if ConFig.SsrPath != config.SsrPath && SsrCmd != nil {
		controller.SSRPath = config.SsrPath
		err := ChangeNode()
		if err != nil {
			erra = fmt.Errorf("%v\nChangeNodeErr -> %v", erra, err)
		}
	}

	// others
	ConFig = config

	return
}

func ProcessInit() (erra error) {
	if ConFig == nil {
		ConFig, _ = config.SettingDecodeJSON()
	}

	MatchCon = controller.NewMatchController(ConFig.BypassFile)
	MatchCon.SetDNS(ConFig.DnsServer, ConFig.IsDNSOverHTTPS)
	_, subnet, err := net.ParseCIDR(ConFig.DnsSubNet)
	if err != nil {
		if net.ParseIP(ConFig.DnsSubNet).To4() != nil {
			_, subnet, _ = net.ParseCIDR(ConFig.DnsSubNet + "/32")
		} else if net.ParseIP(ConFig.DnsSubNet).To16() != nil {
			_, subnet, _ = net.ParseCIDR(ConFig.DnsSubNet + "/128")
		}
	}
	MatchCon.SetDNSSubNet(subnet)
	MatchCon.EnableBYPASS(ConFig.Bypass)
	common.ForwardTarget = MatchCon.Forward
	if ConFig.DNSAcrossProxy {
		MatchCon.EnableDNSProxy()
	}
	controller.SSRPath = ConFig.SsrPath

	_ = ChangeNode()

	LocalListenCon = controller.NewLocalListenController()
	err = LocalListenCon.SetHTTPHost(ConFig.HttpProxyAddress)
	if err != nil {
		erra = fmt.Errorf("UpdateHTTPListenErr -> %v", err)
	}
	err = LocalListenCon.SetSocks5Host(ConFig.Socks5ProxyAddress)
	if err != nil {
		erra = fmt.Errorf("UpdateSOCKS5ListenErr -> %v", err)
	}

	err = LocalListenCon.SetRedirHost(ConFig.RedirProxyAddress)
	if err != nil {
		erra = fmt.Errorf("UpdateRedirListenErr -> %v", err)
	}

	return
}
