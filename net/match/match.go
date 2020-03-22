package match

import (
	"io/ioutil"
	"log"
	"net"
	"strings"
)

type Match struct {
	DNS    func(domain string) (DNS []string, success bool)
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

func (x *Match) Search(str string) (target []string, proxy string) {
	var isMatch bool
	target = []string{}
	if net.ParseIP(str) != nil {
		isMatch, proxy = x.cidr.Search(str)
	} else {
		isMatch, proxy = x.domain.Search(str)
		if !isMatch {
			dnsS, isSuccess := x.DNS(str)
			if isSuccess && len(dnsS) > 0 {
				isMatch, proxy = x.cidr.Search(dnsS[0])
			}
			target = append(target, dnsS...)
		}
	}
	target = append(target, str)
	if isMatch {
		return
	}
	return target, "not found"
}

func NewMatch(dnsFunc func(domain string) (DNS []string, success bool)) *Match {
	cidrMatch := NewCidrMatch()
	domainMatch := NewDomainMatch()
	return &Match{
		DNS:    dnsFunc,
		cidr:   cidrMatch,
		domain: domainMatch,
	}
}

func NewMatchWithFile(dnsFunc func(domain string) (DNS []string, success bool), MatcherFile string) (matcher *Match, err error) {
	cidrMatch := NewCidrMatch()
	domainMatch := NewDomainMatch()
	matcher = &Match{
		DNS:    dnsFunc,
		cidr:   cidrMatch,
		domain: domainMatch,
	}
	configTemp, err := ioutil.ReadFile(MatcherFile)
	if err != nil {
		return
	}
	for _, s := range strings.Split(string(configTemp), "\n") {
		div := strings.Split(s, " ")
		if len(div) < 2 {
			log.Println("format error: " + s)
			continue
		}
		if err := matcher.Insert(div[0], div[1]); err != nil {
			log.Println(err)
			continue
		}
	}
	return matcher, nil
}
