package process

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/controller"
	"github.com/Asutorufa/yuhaiin/subscr"
)

var (
	ConFig         *config.Setting
	LocalListenCon *controller.LocalListen
	MatchCon       *controller.MatchController
	Nodes          *subscr.Node
	first          = true
)

func SetConFig(conf *config.Setting) (erra error) {
	// initialize Match Controller
	if MatchCon == nil {
		MatchCon = controller.NewMatchController(conf.BypassFile)
	}

	// initialize Local Servers Controller
	if LocalListenCon == nil {
		LocalListenCon = controller.NewLocalListenController()
	}

	// DNS
	MatchCon.SetDNS(conf.DnsServer, conf.IsDNSOverHTTPS)

	// Subnet
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

	// DNS proxy
	MatchCon.EnableDNSProxy(conf.DNSAcrossProxy)

	// Bypass or Global
	MatchCon.EnableBYPASS(conf.Bypass)

	// Bypass File Location
	err = MatchCon.SetBypass(conf.BypassFile)
	if err != nil {
		erra = fmt.Errorf("%v\nUpdateMatchErr -> %v", erra, err)
	}

	if (ConFig.SsrPath != conf.SsrPath && ssrRunning) || first {
		err := ChangeNode()
		if err != nil && !first {
			erra = fmt.Errorf("%v\nChangeNodeErr -> %v", erra, err)
		}
	}

	// Local HTTP Server Host
	err = LocalListenCon.SetHTTPHost(conf.HttpProxyAddress)
	if err != nil {
		erra = fmt.Errorf("UpdateHTTPListenErr -> %v", err)
	}

	// Local Socks5 Server Host
	err = LocalListenCon.SetSocks5Host(conf.Socks5ProxyAddress)
	if err != nil {
		erra = fmt.Errorf("UpdateSOCKS5ListenErr -> %v", err)
	}

	// Linux/Darwin Redir Server Host
	err = LocalListenCon.SetRedirHost(conf.RedirProxyAddress)
	if err != nil {
		erra = fmt.Errorf("UpdateRedirListenErr -> %v", err)
	}

	// others
	ConFig = conf
	err = config.SettingEnCodeJSON(ConFig)
	if err != nil {
		erra = fmt.Errorf("%v\nSaveJSON() -> %v", erra, err)
	}

	first = false
	return
}

func Init() (erra error) {
	err := RefreshNodes()
	if err != nil {
		erra = fmt.Errorf("%v\nGetNodes -> %v", erra, err)
	}
	ConFig, _ = config.SettingDecodeJSON()
	err = SetConFig(ConFig)
	if err != nil {
		erra = fmt.Errorf("%v\nSetConfig() -> %v", erra, err)
	}
	return
}

func GetConfig() (*config.Setting, error) {
	return ConFig, nil
}
