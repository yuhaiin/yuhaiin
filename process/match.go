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
	IP       = 3
	block    = 4
	ipDirect = 5
	modes    = map[string]int{"direct": direct, "proxy": proxy, "block": block, "ip": IP, "ipdirect": ipDirect}
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
	Matcher.DNS, err = DNS()
	if err != nil {
		return err
	}

	var domain string
	var mode string
	br := bufio.NewReader(f)
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		_, err = fmt.Sscanf(string(a), "%s %s", &domain, &mode)
		if err != nil {
			continue
		}
		err = Matcher.Insert(domain, modes[strings.ToLower(mode)])
		if err != nil {
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

// https://myexternalip.com/raw
func Forward(host string) (conn net.Conn, err error) {
	if mode != bypass {
		return Conn(host)
	}

	var URI *url.URL
	var md interface{}

	URI, err = url.Parse("//" + host)
	if err != nil {
		goto _proxy
	}

	md = Matcher.Search(URI.Hostname())

	// DIRECT
	if md == direct {
		goto _direct
	}

	// PROXY
	if md == proxy {
		goto _proxy
	}

	// BLOCK
	if md == block {
		return nil, errors.New("block domain: " + host)
	}

	{
		// need to get IP from DNS
		ip, _ := getIP(URI.Hostname())
		if ip == nil {
			goto _proxy
		}
		host = net.JoinHostPort(ip.String(), URI.Port())

		// IP DIRECT
		if md == ipDirect {
			goto _direct
		}

		//IP PROXY
		if md == IP {
			goto _proxy
		}
	}

_proxy:
	return Conn(host)
_direct:
	return net.DialTimeout("tcp", host, 5*time.Second)
}

func getIP(hostname string) (net.IP, error) {
	ips, _ := Matcher.DNS(hostname)
	if len(ips) <= 0 {
		return nil, errors.New("not find")
	}
	return ips[0], nil
}
