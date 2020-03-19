package match

import (
	"io/ioutil"
	"log"
	"net"
	"strings"
)

type Match struct {
	dnsFunc     func(domain string) (DNS []string, success bool)
	cidrMatch   *Cidr
	domainMatch *Domain
}

func (x *Match) Insert(str, mark string) error {
	if _, _, err := net.ParseCIDR(str); err == nil {
		if err = x.cidrMatch.Insert(str, mark); err != nil {
			return err
		}
	} else {
		x.domainMatch.Insert(str, mark)
	}
	return nil
}

func NewMatcher(dnsFunc func(domain string) (DNS []string, success bool)) *Match {
	cidrMatch := NewCidrMatch()
	domainMatch := NewDomainMatcher()
	return &Match{
		dnsFunc:     dnsFunc,
		cidrMatch:   cidrMatch,
		domainMatch: domainMatch,
	}
}

func NewMatcherWithFile(dnsFunc func(domain string) (DNS []string, success bool), MatcherFile string) (matcher *Match, err error) {
	cidrMatch := NewCidrMatch()
	domainMatch := NewDomainMatcher()
	matcher = &Match{
		dnsFunc:     dnsFunc,
		cidrMatch:   cidrMatch,
		domainMatch: domainMatch,
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

func (x *Match) Search(str string) (target []string, proxy string) {
	var isMatch bool
	target = []string{}
	if net.ParseIP(str) != nil {
		isMatch, proxy = x.cidrMatch.Search(str)
		//log.Println(isMatch, proxy)
	} else {
		isMatch, proxy = x.domainMatch.Search(str)
		if !isMatch {
			dnsS, isSuccess := x.dnsFunc(str)
			if isSuccess && len(dnsS) > 0 {
				isMatch, proxy = x.cidrMatch.Search(dnsS[0])
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
