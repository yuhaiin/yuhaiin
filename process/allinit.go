package process

import (
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/common"
)

var (
	conFig, _ = config.SettingDecodeJSON()
)

func UpdateConFig() {
	conFig, _ = config.SettingDecodeJSON()
}

func SetConFig(config *config.Setting) {
	if conFig.DnsServer != config.DnsServer || conFig.IsDNSOverHTTPS != config.IsDNSOverHTTPS {
		UpdateDNS(config.DnsServer, config.IsDNSOverHTTPS)
	}

	if conFig.DnsSubNet != config.DnsSubNet {
		UpdateDNSSubNet(net.ParseIP(config.DnsSubNet))
	}

	if conFig.HttpProxyAddress != config.HttpProxyAddress || conFig.Socks5ProxyAddress != config.Socks5ProxyAddress || conFig.RedirProxyAddress != config.RedirProxyAddress {
		conFig.HttpProxyAddress = config.HttpProxyAddress
		conFig.Socks5ProxyAddress = config.Socks5ProxyAddress
		conFig.RedirProxyAddress = config.RedirProxyAddress
		err := UpdateListen()
		if err != nil {
			log.Println(err)
		}
	}

	if conFig.SsrPath != config.SsrPath {
		conFig.SsrPath = config.SsrPath
		_ = ChangeNode()
	}

	if conFig.BypassFile != config.BypassFile {
		conFig.BypassFile = config.BypassFile
		_ = UpdateMatch()
	}

	// mode
	// icon
	conFig = config
}

func processInit() error {
	//UpdateDNS(conFig.DnsServer)
	if err := UpdateMatch(); err != nil {
		return err
	}
	common.ForwardTarget = Forward
	//if err := UpdateListen(); err != nil {
	//	return err
	//}
	_ = ChangeNode()
	return nil
}
