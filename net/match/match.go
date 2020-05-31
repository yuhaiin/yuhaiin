package match

import (
	"net"
)

type Match struct {
	DNS func(domain string) (DNS []net.IP, err error)
	//DNSStr string
	cidr   *Cidr
	domain *Domain
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
	if des != nil || x.DNS == nil {
		goto _end
	}

	if dnsS, _ := x.DNS(str); len(dnsS) > 0 {
		_, des = x.cidr.Search(dnsS[0].String())
	}

_end:
	mCache.Add(str, des)
	return
}

func NewMatch(dnsFunc func(domain string) (DNS []net.IP, err error)) (matcher Match) {
	return Match{
		DNS:    dnsFunc,
		cidr:   NewCidrMatch(),
		domain: NewDomainMatch(),
	}
}
