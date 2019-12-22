package matcher

import (
	"SsrMicroClient/net/cidrmatch"
	"SsrMicroClient/net/dns"
	"SsrMicroClient/net/domainmatch"
)

type Match struct {
	DNSServer         string
	cidrMatch         *cidrmatch.CidrMatch
	CidrFile          string
	bypassDomainMatch *domainmatch.DomainMatcher
	BypassDomainFile  string
	directProxy       *domainmatch.DomainMatcher
	DirectProxyFile   string
	discordDomain     *domainmatch.DomainMatcher
	DiscordDomainFile string
}

type Last struct {
	Domain  bool
	Proxy   bool
	Discord bool
	Host    string
}

func NewMatch(DNS, CidrFile, BypassDomainFile, DirectProxyFile, DiscordDomainFile string) (*Match, error) {
	var err error
	var match Match
	match.DNSServer = DNS
	match.CidrFile = CidrFile
	match.BypassDomainFile = BypassDomainFile
	match.DirectProxyFile = DirectProxyFile
	match.DiscordDomainFile = DiscordDomainFile
	match.bypassDomainMatch = domainmatch.NewDomainMatcherWithFile(match.BypassDomainFile)
	match.directProxy = domainmatch.NewDomainMatcherWithFile(match.DirectProxyFile)
	match.discordDomain = domainmatch.NewDomainMatcherWithFile(match.DiscordDomainFile)
	match.cidrMatch, err = cidrmatch.NewCidrMatchWithTrie(match.CidrFile)
	if err != nil {
		return &Match{}, err
	}
	return &match, nil
}

func (match *Match) Matcher(host, port string, domain bool) Last {
	if domain {
		if match.discordDomain.Search(host) {
			return Last{Discord: true}
		} else if match.bypassDomainMatch.Search(host) {
			return Last{Domain: true, Proxy: false, Discord: false, Host: host}
		} else if match.directProxy.Search(host) {
			return Last{Domain: true, Proxy: true, Discord: false, Host: host}
		}

		dnsS, isSuccess := dns.DNS(match.DNSServer, host)
		if isSuccess {
			if match.cidrMatch.MatchWithTrie(dnsS[0]) {
				return Last{Proxy: false, Domain: false, Discord: false, Host: dnsS[0]}
			}
			return Last{Proxy: true, Domain: false, Discord: false, Host: dnsS[0]}
		}
		return Last{Proxy: true, Domain: true, Discord: false, Host: host}
	} else {
		if match.cidrMatch.MatchWithTrie(host) {
			return Last{Domain: false, Proxy: false, Discord: false, Host: host}
		}
		return Last{Domain: false, Proxy: true, Discord: false, Host: host}
	}
}
