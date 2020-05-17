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
	if _, _, err := net.ParseCIDR(str); err == nil {
		if err = x.cidr.Insert(str, mark); err != nil {
			return err
		}
	} else {
		x.domain.Insert(str, mark)
	}
	return nil
}

func (x *Match) Search(str string) (des interface{}) {
	var isMatch = false
	if des, isCache := mCache.Get(str); isCache {
		return des
	}
	switch net.ParseIP(str) {
	case nil:
		if isMatch, des = x.domain.Search(str); !isMatch && x.DNS != nil {
			if dnsS, isSuccess := x.DNS(str); isSuccess && len(dnsS) > 0 {
				isMatch, des = x.cidr.Search(dnsS[0].String())
			}
		}
	default:
		isMatch, des = x.cidr.Search(str)
	}
	if isMatch {
		mCache.Add(str, des)
		return
	}
	return nil
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
