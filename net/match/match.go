package match

import (
	"io/ioutil"
	"net"
	"strings"
)

type Match struct {
	DNS func(domain string) (DNS []net.IP, success bool)
	//DNSStr string
	cidr   *Cidr
	domain *Domain
}

func (x *Match) Insert(str, mark string) error {
	if _, _, err := net.ParseCIDR(str); err == nil {
		if err = x.cidr.Insert(str, mark); err != nil {
			return err
		}
	} else {
		x.domain.Insert(str, mark)
	}
	return nil
}

func (x *Match) Search(str string) (des string) {
	var isMatch = false
	if des, isCache := mCache.Get(str); isCache {
		return des.(string)
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
	return "not found"
}

func NewMatch(dnsFunc func(domain string) (DNS []net.IP, success bool), MatcherFile string) (matcher *Match, err error) {
	cidrMatch := NewCidrMatch()
	domainMatch := NewDomainMatch()
	matcher = &Match{
		DNS:    dnsFunc,
		cidr:   cidrMatch,
		domain: domainMatch,
	}
	if MatcherFile == "" {
		return matcher, nil
	}
	configTemp, err := ioutil.ReadFile(MatcherFile)
	if err != nil {
		return
	}
	for _, s := range strings.Split(string(configTemp), "\n") {
		div := strings.Split(s, " ")
		if len(div) < 2 {
			continue
		}
		if err := matcher.Insert(div[0], div[1]); err != nil {
			continue
		}
	}
	return matcher, nil
}
