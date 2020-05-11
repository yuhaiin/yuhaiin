package process

import (
	"errors"
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/Asutorufa/yuhaiin/net/dns"
	"github.com/Asutorufa/yuhaiin/net/match"
	"log"
	"net"
	"net/url"
	"time"
)

var (
	bypass       = 0
	globalDirect = 1
	globalProxy  = 2
)

var (
	mode    int
	Matcher match.Match
	Conn    func(host string) (conn net.Conn, err error)
)

func init() {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		log.Print(err)
	}
	if conFig.Bypass {
		mode = bypass
	} else {
		mode = globalProxy
	}
	Matcher, err = match.NewMatch2(nil, conFig.BypassFile)
	if err != nil {
		log.Print(err)
	}
	if Matcher.DNS, err = DNS(); err != nil {
		log.Print(err)
		return
	}
	common.ForwardTarget = Forward
}

func UpdateMode() error {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return err
	}
	if conFig.Bypass {
		mode = bypass
	} else {
		mode = globalProxy
	}
	return nil
}

func UpdateDNS() error {
	var err error
	if Matcher.DNS, err = DNS(); err != nil {
		return err
	}
	return nil
}

func UpdateMatch() error {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return err
	}
	Matcher, err = match.NewMatch2(nil, conFig.BypassFile)
	if err != nil {
		return err
	}
	if Matcher.DNS, err = DNS(); err != nil {
		return err
	}
	return nil
}

func DNS() (func(domain string) (DNS []net.IP, success bool), error) {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return nil, err
	}
	if conFig.IsDNSOverHTTPS {
		return func(domain string) (DNS []net.IP, success bool) {
			return dns.DNSOverHTTPS(conFig.DnsServer, domain, nil)
		}, nil
	}
	return func(domain string) (DNS []net.IP, success bool) {
		DNS, success, _ = dns.MDNS(conFig.DnsServer, domain)
		return
	}, nil
}

func Forward(host string) (conn net.Conn, err error) {
	if mode == bypass {
		URI, err := url.Parse("//" + host)
		if err != nil {
			return nil, err
		}
		if URI.Port() == "" {
			host = net.JoinHostPort(host, "80")
			if URI, err = url.Parse("//" + host); err != nil {
				return nil, err
			}
		}

		switch Matcher.Search(URI.Hostname()) {
		case "direct":
			return net.DialTimeout("tcp", host, 3*time.Second)
		case "localDNS":
			if ips, isSuccess := Matcher.DNS(URI.Hostname()); isSuccess {
				for _, ip := range ips {
					return Conn(ip.String() + ":" + URI.Port())
				}
			}
		case "block":
			return nil, errors.New("block domain: " + host)
		}
	}
	return Conn(host)
}
