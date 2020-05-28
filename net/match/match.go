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

	var isMatch = false
	switch net.ParseIP(str) {
	case nil:
		isMatch, des = x.domain.Search(str)
		if isMatch || x.DNS == nil {
			break
		}

		dnsS, isSuccess := x.DNS(str)
		if isSuccess && len(dnsS) > 0 {
			isMatch, des = x.cidr.Search(dnsS[0].String())
		}
	default:
		isMatch, des = x.cidr.Search(str)
	}

	if !isMatch {
		return nil
	}
	mCache.Add(str, des)
	return
}

func NewMatch(dnsFunc func(domain string) (DNS []net.IP, success bool)) (matcher Match) {
	cidrMatch := NewCidrMatch()
	domainMatch := NewDomainMatch()
	matcher = Match{
		DNS:    dnsFunc,
		cidr:   cidrMatch,
		domain: domainMatch,
	}
	return matcher
}
