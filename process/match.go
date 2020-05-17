package process

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/Asutorufa/yuhaiin/net/dns"
	"github.com/Asutorufa/yuhaiin/net/match"
)

var (
	bypass       = 0
	globalDirect = 1
	globalProxy  = 2
)

var (
	others   = 0
	direct   = 1
	proxy    = 2
	localDNS = 3
	block    = 4
	modes    = map[string]int{"direct": direct, "proxy": proxy, "block": block, "localdns": localDNS}
)

var (
	mode    int
	Matcher match.Match
	Conn    func(host string) (conn net.Conn, err error)
)

func matchInit() {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		log.Print(err)
	}
	if conFig.Bypass {
		mode = bypass
	} else {
		mode = globalProxy
	}
	if err = UpdateMatch(); err != nil {
		log.Println(err)
	}
	common.ForwardTarget = Forward
}

func UpdateMatch() error {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return err
	}

	f, err := os.Open(conFig.BypassFile)
	if err != nil {
		return err
	}
	defer f.Close()

	Matcher = match.NewMatch(nil)
	if Matcher.DNS, err = DNS(); err != nil {
		return err
	}

	br := bufio.NewReader(f)
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		var domain string
		var mode string
		if _, err := fmt.Sscanf(string(a), "%s %s", &domain, &mode); err != nil {
			continue
		}
		if err = Matcher.Insert(domain, modes[strings.ToLower(mode)]); err != nil {
			continue
		}
	}
	return nil
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
		switch Matcher.Search(URI.Hostname()) {
		case direct:
			return net.DialTimeout("tcp", host, 3*time.Second)
		case localDNS:
			if ips, isSuccess := Matcher.DNS(URI.Hostname()); isSuccess {
				for _, ip := range ips {
					return Conn(net.JoinHostPort(ip.String(), URI.Port()))
				}
			}
		case block:
			return nil, errors.New("block domain: " + host)
		}
	}
	return Conn(host)
}
