package matcher

import (
	"io/ioutil"
	"log"
	"net"
	"strings"

	"SsrMicroClient/net/dns"
	"SsrMicroClient/net/matcher/cidrmatch"
	"SsrMicroClient/net/matcher/domainmatch"
)

type Match struct {
	IsDNSOverHTTPS bool
	DNSServer      string
	cidrMatch      *cidrmatch.CidrMatch
	domainMatch    *domainmatch.DomainMatcher
}

func (newMatch *Match) InsertOne(str, mark string) error {
	if _, _, err := net.ParseCIDR(str); err == nil {
		if err = newMatch.cidrMatch.InsetOneCIDR(str, mark); err != nil {
			return err
		}
	} else {
		newMatch.domainMatch.Insert(str, mark)
	}
	return nil
}

func NewMatcher(DNSServer string) *Match {
	cidrMatch := cidrmatch.NewCidrMatch()
	domainMatch := domainmatch.NewDomainMatcher()
	return &Match{
		DNSServer:   DNSServer,
		cidrMatch:   cidrMatch,
		domainMatch: domainMatch,
	}
}

func NewMatcherWithFile(DNSServer string, MatcherFile string) (matcher *Match, err error) {
	cidrMatch := cidrmatch.NewCidrMatch()
	domainMatch := domainmatch.NewDomainMatcher()
	matcher = &Match{
		DNSServer:   DNSServer,
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
		if err := matcher.InsertOne(div[0], div[1]); err != nil {
			log.Println(err)
			continue
		}
	}
	return matcher, nil
}

func (newMatch *Match) MatchStr(str string) (target []string, proxy string) {
	var isMatch bool
	target = []string{}
	if net.ParseIP(str) != nil {
		isMatch, proxy = newMatch.cidrMatch.MatchOneIP(str)
		//log.Println(isMatch, proxy)
	} else {
		isMatch, proxy = newMatch.domainMatch.Search(str)
		if !isMatch {
			if newMatch.IsDNSOverHTTPS {
				if dnsS, isSuccess := dns.DNSOverHTTPS(newMatch.DNSServer, str); isSuccess {
					isMatch, proxy = newMatch.cidrMatch.MatchOneIP(dnsS[0])
					target = append(target, dnsS...)
				}
			} else {
				if dnsS, isSuccess := dns.DNS(newMatch.DNSServer, str); isSuccess {
					isMatch, proxy = newMatch.cidrMatch.MatchOneIP(dnsS[0])
					target = append(target, dnsS...)
				}
			}
		}
	}
	target = append(target, str)
	if isMatch {
		return
	}
	return target, "not found"
}
