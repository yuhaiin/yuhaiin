package controller

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
	Proxy = func(host string) (conn net.Conn, err error) { return net.DialTimeout("tcp", host, time.Second*7) }
)

type MatchController struct {
	isBypass   bool
	bypassFile string
	Matcher    *match.Match
}

func NewMatchController(bypassFile string) *MatchController {
	m := &MatchController{}
	m.bypassFile = bypassFile
	m.Matcher = match.NewMatch()
	_ = m.UpdateMatch()
	return m
}

func (m *MatchController) EnableBYPASS(enable bool) {
	m.isBypass = enable
}

func (m *MatchController) UpdateMatch() error {
	f, err := os.Open(m.bypassFile)
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
		err = m.Matcher.Insert(domain, modes[strings.ToLower(mode)])
		if err != nil {
			continue
		}
	}
	return nil
}

func (m *MatchController) SetBypass(file string) error {
	m.bypassFile = file
	return m.UpdateMatch()
}

func (m *MatchController) SetDNS(server string, doh bool) {
	m.Matcher.SetDNS(server, doh)
}

func (m *MatchController) SetDNSSubNet(ip net.IP) {
	if m.Matcher.DNS == nil {
		return
	}
	m.Matcher.DNS.SetSubnet(ip)
}

// https://myexternalip.com/raw
func (m *MatchController) Forward(host string) (conn net.Conn, err error) {
	if !m.isBypass {
		return Proxy(host)
	}

	var URI *url.URL
	var md match.Des

	URI, err = url.Parse("//" + host)
	if err != nil {
		goto _proxy
	}

	md = m.Matcher.Search(URI.Hostname())

	switch md.Des {
	case direct:
		goto _direct
	case proxy:
		goto _proxy
	case block:
		return nil, errors.New("block domain: " + host)
	}

	{
		// need to get IP from DNS
		var ip net.IP
		if len(md.DNS) > 0 {
			ip = md.DNS[0]
		} else {
			ip, _ = m.getIP(URI.Hostname())
		}
		if ip == nil {
			goto _proxy
		}
		host = net.JoinHostPort(ip.String(), URI.Port())

		switch md.Des {
		case ipDirect:
			goto _direct
		case IP:
			goto _proxy
		}
	}

_proxy:
	return Proxy(host)
_direct:
	return net.DialTimeout("tcp", host, 5*time.Second)
}

func (m *MatchController) getIP(hostname string) (net.IP, error) {
	ips := m.Matcher.GetIP(hostname)
	if len(ips) <= 0 {
		return nil, errors.New("not find")
	}
	return ips[0], nil
}
