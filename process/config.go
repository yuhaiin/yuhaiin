package process

import "C"
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
)

func SetConFig(conf *config.Setting) (erra error) {
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
	err = MatchCon.SetAllOption(func(option *controller.OptionMatchCon) {
		option.DNS.Server = conf.DnsServer
		option.DNS.Proxy = conf.DNSAcrossProxy
		option.DNS.DOH = conf.IsDNSOverHTTPS
		option.DNS.Subnet = subnet
		option.Bypass = conf.Bypass
		option.BypassPath = conf.BypassFile
	})
	if err != nil {
		erra = fmt.Errorf("%v\n Set Match Controller Options -> %v", erra, err)
	}

	if ConFig.SsrPath != conf.SsrPath && ssrRunning {
		err := ChangeNode()
		if err != nil {
			erra = fmt.Errorf("%v\nChangeNodeErr -> %v", erra, err)
		}
	}

	err = LocalListenCon.SetAHost(
		controller.WithHTTP(conf.HttpProxyAddress),
		controller.WithSocks5(conf.Socks5ProxyAddress),
		controller.WithRedir(conf.RedirProxyAddress),
	)

	if err != nil {
		erra = fmt.Errorf("%v\n Set Local Listener Controller Options -> %v", erra, err)
	}
	// others
	ConFig = conf
	err = config.SettingEnCodeJSON(ConFig)
	if err != nil {
		erra = fmt.Errorf("%v\nSaveJSON() -> %v", erra, err)
	}
	return
}

func Init() error {
	err := RefreshNodes()
	if err != nil {
		return fmt.Errorf("RefreshNodes -> %v", err)
	}

	ConFig, err = config.SettingDecodeJSON()
	if err != nil {
		return fmt.Errorf("DecodeJson -> %v", err)
	}

	_, subnet, err := net.ParseCIDR(ConFig.DnsSubNet)
	if err != nil {
		if net.ParseIP(ConFig.DnsSubNet).To4() != nil {
			_, subnet, _ = net.ParseCIDR(ConFig.DnsSubNet + "/32")
		}

		if net.ParseIP(ConFig.DnsSubNet).To16() != nil {
			_, subnet, _ = net.ParseCIDR(ConFig.DnsSubNet + "/128")
		}
	}
	// initialize Match Controller
	MatchCon, err = controller.NewMatchCon(ConFig.BypassFile, func(option *controller.OptionMatchCon) {
		option.DNS.Server = ConFig.DnsServer
		option.DNS.Proxy = ConFig.DNSAcrossProxy
		option.DNS.DOH = ConFig.IsDNSOverHTTPS
		option.DNS.Subnet = subnet
		option.Bypass = ConFig.Bypass
	})
	if err != nil {
		return fmt.Errorf("new Match Controller -> %v", err)
	}

	// initialize Local Servers Controller
	LocalListenCon, err = controller.NewLocalListenCon(
		controller.WithHTTP(ConFig.HttpProxyAddress),
		controller.WithSocks5(ConFig.Socks5ProxyAddress),
		controller.WithRedir(ConFig.RedirProxyAddress),
		controller.WithTCPConn(MatchCon.Forward),
	)
	if err != nil {
		return fmt.Errorf("new Local Listener Controller -> %v", err)
	}

	_ = ChangeNode()
	return nil
}

func GetConfig() (*config.Setting, error) {
	return ConFig, nil
}
