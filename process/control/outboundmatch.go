package ServerControl

import (
	"errors"
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/dns"
	"github.com/Asutorufa/yuhaiin/net/match"
	"net"
	"net/url"
	"time"
)

type OutboundMatch struct {
	Matcher *match.Match
	conn    func(host string) (conn net.Conn, err error)
}

func DNS() (func(domain string) (DNS []string, success bool), error) {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return nil, err
	}
	if conFig.IsDNSOverHTTPS {
		return func(domain string) (DNS []string, success bool) {
			return dns.DNSOverHTTPS(conFig.DnsServer, domain, nil)
		}, nil
	}
	return func(domain string) (DNS []string, success bool) {
		return dns.DNS(conFig.DnsServer, domain)
	}, nil
}

func NewOutboundMatch(forward func(host string) (conn net.Conn, err error)) (*OutboundMatch, error) {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return nil, err
	}
	nMatch, err := match.NewMatch(nil, conFig.BypassFile)
	if err != nil {
		return nil, err
	}
	nMatch.DNSStr = conFig.DnsServer
	return &OutboundMatch{
		Matcher: nMatch,
		conn:    forward,
	}, nil
}

func (f *OutboundMatch) ChangeForward(conn func(host string) (conn net.Conn, err error)) {
	f.conn = conn
}

func (f *OutboundMatch) UpdateDNSStr() error {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return err
	}
	f.Matcher.DNSStr = conFig.DnsServer
	return nil
}

func (f *OutboundMatch) UpdateDNS() error {
	dNS, err := DNS()
	if err != nil {
		return err
	}
	f.Matcher.DNS = dNS
	return nil
}

func (f *OutboundMatch) Forward(host string) (conn net.Conn, err error) {
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

	switch f.Matcher.Search2(URI.Hostname()) {
	case "direct":
		return net.DialTimeout("tcp", host, 3*time.Second)
	case "block":
		return nil, errors.New("block domain: " + host)
	}
	return f.conn(host)
}
