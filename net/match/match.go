package match

import (
	"net"
	"net/url"

	"github.com/Asutorufa/yuhaiin/net/dns"
)

type Match struct {
	dns func(domain string) (DNS []net.IP, err error)
	//DNSStr string
	cidr   *Cidr
	domain *Domain
}

func (x *Match) SetDNS(host string) {
	urls, err := url.Parse("//" + host)
	if err != nil {
		return
	}
	if net.ParseIP(urls.Hostname()) != nil {
		x.dns = func(domain string) (DNS []net.IP, err error) {
			return dns.DNS(host, domain)
		}
	}
	x.dns = func(domain string) (DNS []net.IP, err error) {
		return dns.DOH(host, domain)
	}
}

func (x *Match) DNS(domain string) (ip []net.IP) {
	if x.dns == nil {
		return nil
	}
	ip, _ = x.dns(domain)
	return
}

func (x *Match) Insert(str string, mark interface{}) error {
	if _, _, err := net.ParseCIDR(str); err != nil {
		x.domain.InsertFlip(str, mark)
		return nil
	}

	return x.cidr.Insert(str, mark)
}

func (x *Match) Search(str string) (des interface{}) {
	if des, _ = mCache.Get(str); des != nil {
		return des
	}

	if net.ParseIP(str) != nil {
		_, des = x.cidr.Search(str)
		goto _end
	}

	_, des = x.domain.SearchFlip(str)
	if des != nil || x.dns == nil {
		goto _end
	}

	if dnsS, _ := x.dns(str); len(dnsS) > 0 {
		_, des = x.cidr.Search(dnsS[0].String())
	}

_end:
	mCache.Add(str, des)
	return
}

func NewMatch(dns string) (matcher Match) {
	m := Match{
		cidr:   NewCidrMatch(),
		domain: NewDomainMatch(),
	}
	m.SetDNS(dns)
	return m
}
