package ServerControl

import (
	"errors"
	"github.com/Asutorufa/SsrMicroClient/config"
	"github.com/Asutorufa/SsrMicroClient/net/dns"
	"github.com/Asutorufa/SsrMicroClient/net/match"
	"net"
	"time"
)

type OutboundMatch struct {
	Matcher *match.Match
	conn    func(host string) (conn net.Conn, err error)
}

func DNS() (func(domain string) (DNS []string, success bool), error) {
	conFig, err := config.SettingDecodeJSON2()
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
	conFig, err := config.SettingDecodeJSON2()
	if err != nil {
		return nil, err
	}
	dNS, err := DNS()
	if err != nil {
		return nil, err
	}
	nMatch, err := match.NewMatchWithFile(dNS, conFig.BypassFile)
	if err != nil {
		return nil, err
	}
	return &OutboundMatch{
		Matcher: nMatch,
		conn:    forward,
	}, nil
}

func (f *OutboundMatch) ChangeForward(conn func(host string) (conn net.Conn, err error)) {
	f.conn = conn
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
	ip, bypass := f.Matcher.Search(host)
	switch bypass {
	case "direct":
		for i := range ip {
			conn, err := net.DialTimeout("tcp", ip[i], 5*time.Second)
			if err == nil {
				return conn, err
			}
		}
	case "block":
		return nil, errors.New("block domain: " + host)
	case "proxy":
		return f.conn(host)
	}
	return net.DialTimeout("tcp", host, 5*time.Second)
}
