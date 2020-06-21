package process

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/net/dns"

	"github.com/Asutorufa/yuhaiin/net/match"
)

var (
	bypass       = 0
	globalDirect = 1
	globalProxy  = 2
)

type todo int

var (
	others   todo = 0
	direct   todo = 1
	proxy    todo = 2
	IP       todo = 3
	block    todo = 4
	ipDirect todo = 5
	modes         = map[string]todo{"direct": direct, "proxy": proxy, "block": block, "ip": IP, "ipdirect": ipDirect}
)

type insertData struct {
	Type  todo
	other string
}

var (
	Matcher = match.NewMatch(conFig.DnsServer)
	Conn    = func(host string) (conn net.Conn, err error) { return net.DialTimeout("tcp", host, time.Second*7) }
)

func UpdateMatch() error {
	f, err := os.Open(conFig.BypassFile)
	if err != nil {
		return err
	}
	defer f.Close()

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

func UpdateDNS(host string) {
	Matcher.SetDNS(host)
}

func UpdateDNSSubNet(ip net.IP) {
	if ip == nil {
		return
	}
	dns.Subnet = net.ParseIP("0.0.0.0")
}

// https://myexternalip.com/raw
func Forward(host string) (conn net.Conn, err error) {
	if !conFig.Bypass {
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
	ips := Matcher.DNS(hostname)
	if len(ips) <= 0 {
		return nil, errors.New("not find")
	}
	return ips[0], nil
}
