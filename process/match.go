package process

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/Asutorufa/yuhaiin/net/dns"
	"github.com/Asutorufa/yuhaiin/net/match"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
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
	if err := UpdateMode(); err != nil {
		log.Println(err)
	}

	if err := UpdateMatch(); err != nil {
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
	if !conFig.Bypass {
		mode = globalProxy
	}
	mode = bypass
	return nil
}

func UpdateDNS() error {
	var err error
	if Matcher.DNS, err = DNS(); err != nil {
		return err
	}
	return nil
}

func DNS() (func(domain string) (DNS []net.IP, err error), error) {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return nil, err
	}

	if conFig.IsDNSOverHTTPS {
		return func(domain string) (DNS []net.IP, err error) {
			return dns.DOH(conFig.DnsServer, domain)
		}, nil
	}

	return func(domain string) (DNS []net.IP, err error) {
		return dns.DNS(conFig.DnsServer, domain)
	}, nil
}

func Forward(host string) (conn net.Conn, err error) {
	if mode != bypass {
		return Conn(host)
	}

	URI, err := url.Parse("//" + host)
	if err != nil {
		return nil, err
	}

	switch Matcher.Search(URI.Hostname()) {
	case direct:
		//log.Println("direct: ",URI.Hostname())
		return net.DialTimeout("tcp", host, 5*time.Second)

	case localDNS:
		//log.Println("localDNS: ",URI.Hostname())
		ips, err := Matcher.DNS(URI.Hostname())
		if err != nil {
			break
		}
		for _, ip := range ips {
			return Conn(net.JoinHostPort(ip.String(), URI.Port()))
		}

	case block:
		//log.Println("block: ",URI.Hostname())
		return nil, errors.New("block domain: " + host)
	}
	//log.Println("proxy: ",URI.Hostname())
	return Conn(host)
}
