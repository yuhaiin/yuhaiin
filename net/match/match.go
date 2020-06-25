package match

import (
	"net"

	"github.com/Asutorufa/yuhaiin/net/dns"
)

type Match struct {
	DNS dns.DNS
	//DNSStr string
	cidr   *Cidr
	domain *Domain
}

type Des struct {
	Des interface{}
	DNS []net.IP
}

func (x *Match) SetDNS(host string, doh bool) {
	var subnet net.IP
	if x.DNS != nil {
		subnet = x.DNS.GetSubnet()
	}
	if doh {
		x.DNS = dns.NewDOH(host)
	} else {
		x.DNS = dns.NewNormalDNS(host)
	}
	x.DNS.SetSubnet(subnet)
}

func (x *Match) GetIP(domain string) (ip []net.IP) {
	if x.DNS == nil {
		return nil
	}
	ip, _ = x.DNS.Search(domain)
	return
}

func (x *Match) Insert(str string, mark interface{}) error {
	if _, _, err := net.ParseCIDR(str); err != nil {
		x.domain.InsertFlip(str, mark)
		return nil
	}

	return x.cidr.Insert(str, mark)
}

func (x *Match) Search(str string) Des {
	d := Des{}
	if des, _ := mCache.Get(str); des != nil {
		return des.(Des)
	}

	if net.ParseIP(str) != nil {
		_, d.Des = x.cidr.Search(str)
		goto _end
	}

	_, d.Des = x.domain.SearchFlip(str)
	if d.Des != nil || x.DNS == nil {
		goto _end
	}

	if dnsS, _ := x.DNS.Search(str); len(dnsS) > 0 {
		d.DNS = dnsS
		_, d.Des = x.cidr.Search(dnsS[0].String())
	}

_end:
	mCache.Add(str, d)
	return d
}

func NewMatch() (matcher *Match) {
	m := &Match{
		cidr:   NewCidrMatch(),
		domain: NewDomainMatch(),
	}
	return m
}
