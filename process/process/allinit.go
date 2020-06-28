package process

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/subscr"

	"github.com/Asutorufa/yuhaiin/process/controller"

	"github.com/Asutorufa/yuhaiin/config"
)

var (
	ConFig         *config.Setting
	LocalListenCon *controller.LocalListen
	MatchCon       *controller.MatchController
	Nodes          *subscr.Node
)

func SetConFig(conf *config.Setting, first bool) (erra error) {
	if first {
		MatchCon = controller.NewMatchController(conf.BypassFile)
		LocalListenCon = controller.NewLocalListenController()
	}

	if ConFig.DnsServer != conf.DnsServer || ConFig.IsDNSOverHTTPS != conf.IsDNSOverHTTPS || first {
		MatchCon.SetDNS(conf.DnsServer, conf.IsDNSOverHTTPS)
	}

	if ConFig.DnsSubNet != conf.DnsSubNet || first {
		_, subnet, err := net.ParseCIDR(conf.DnsSubNet)
		if err != nil {
			if net.ParseIP(conf.DnsSubNet).To4() != nil {
				_, subnet, _ = net.ParseCIDR(conf.DnsSubNet + "/32")
			}

			if net.ParseIP(conf.DnsSubNet).To16() != nil {
				_, subnet, _ = net.ParseCIDR(conf.DnsSubNet + "/128")
			}
		}
		MatchCon.SetDNSSubNet(subnet)
	}

	if ConFig.DNSAcrossProxy != conf.DNSAcrossProxy || first {
		MatchCon.EnableDNSProxy(conf.DNSAcrossProxy)
	}

	if ConFig.Bypass != conf.Bypass || first {
		MatchCon.EnableBYPASS(conf.Bypass)
	}

	if ConFig.BypassFile != conf.BypassFile || first {
		err := MatchCon.SetBypass(conf.BypassFile)
		if err != nil {
			erra = fmt.Errorf("%v\nUpdateMatchErr -> %v", erra, err)
		}
	}

	if (ConFig.SsrPath != conf.SsrPath && SsrCmd != nil) || first {
		controller.SSRPath = conf.SsrPath
		err := ChangeNode()
		if err != nil {
			if !first {
				erra = fmt.Errorf("%v\nChangeNodeErr -> %v", erra, err)
			}
		}
	}

	if ConFig.HttpProxyAddress != conf.HttpProxyAddress || first {
		err := LocalListenCon.SetHTTPHost(conf.HttpProxyAddress)
		if err != nil {
			erra = fmt.Errorf("UpdateHTTPListenErr -> %v", err)
		}
	}
	if ConFig.Socks5ProxyAddress != conf.Socks5ProxyAddress || first {
		err := LocalListenCon.SetSocks5Host(conf.Socks5ProxyAddress)
		if err != nil {
			erra = fmt.Errorf("UpdateSOCKS5ListenErr -> %v", err)
		}
	}

	if ConFig.RedirProxyAddress != conf.RedirProxyAddress || first {
		err := LocalListenCon.SetRedirHost(conf.RedirProxyAddress)
		if err != nil {
			erra = fmt.Errorf("UpdateRedirListenErr -> %v", err)
		}
	}

	// others
	ConFig = conf

	err := config.SettingEnCodeJSON(ConFig)
	if err != nil {
		erra = fmt.Errorf("%v\nSaveJSON() -> %v", erra, err)
	}

	return
}

func ProcessInit() (erra error) {
	var err error
	err = RefreshNodes()
	if err != nil {
		erra = fmt.Errorf("%v\nGetNodes -> %v", erra, err)
	}
	ConFig, _ = config.SettingDecodeJSON()
	err = SetConFig(ConFig, true)
	if err != nil {
		erra = fmt.Errorf("%v\nSetConfig() -> %v", erra, err)
	}
	return
}

func GetConfig() (*config.Setting, error) {
	return ConFig, nil
}
