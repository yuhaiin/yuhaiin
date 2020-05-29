package match

import (
	"net"
)

type Match struct {
	DNS func(domain string) (DNS []net.IP, success bool)
	//DNSStr string
	cidr   *Cidr
	domain *Domain
}

func (x *Match) Insert(str string, mark interface{}) error {
	if _, _, err := net.ParseCIDR(str); err != nil {
		x.domain.Insert(str, mark)
		return nil
	}

	return x.cidr.Insert(str, mark)
}

func (x *Match) Search(str string) (des interface{}) {
	if des, isCache := mCache.Get(str); isCache {
		return des
	}

	var isMatch bool
	if net.ParseIP(str) != nil {
		isMatch, des = x.cidr.Search(str)
		goto _end
	}

	isMatch, des = x.domain.Search(str)
	if isMatch || x.DNS == nil {
		goto _end
	}

	if dnsS, isSuccess := x.DNS(str); isSuccess && len(dnsS) > 0 {
		isMatch, des = x.cidr.Search(dnsS[0].String())
	}

_end:
	mCache.Add(str, des)
	return
}

func NewMatch(dnsFunc func(domain string) (DNS []net.IP, success bool)) (matcher Match) {
	return Match{
		DNS:    dnsFunc,
		cidr:   NewCidrMatch(),
		domain: NewDomainMatch(),
	}
}
