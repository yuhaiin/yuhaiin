package matcher

import (
	"SsrMicroClient/net/dns"
	"testing"
)

func TestNewMatcher(t *testing.T) {
	dnsFunc := func(domain string) ([]string, bool) {
		return dns.DNS("119.29.29.29:53", domain)
	}
	matcher := NewMatcher(dnsFunc)
	if err := matcher.InsertOne("www.baidu.com", "test_baidu"); err != nil {
		t.Error(err)
	}
	if err := matcher.InsertOne("10.2.2.1/18", "test_cidr"); err != nil {
		t.Error(err)
	}
	t.Log(matcher.MatchStr("10.2.2.1"))
	t.Log(matcher.MatchStr("www.baidu.com"))
	t.Log(matcher.MatchStr("www.google.com"))
}

func TestNewMatcherWithFile(t *testing.T) {
	dnsFunc := func(domain string) ([]string, bool) {
		return dns.DNS("119.29.29.29:53", domain)
	}
	matcher, err := NewMatcherWithFile(dnsFunc, "../../rule/rule.config")
	if err != nil {
		t.Error(err)
	}
	t.Log(matcher.MatchStr("10.2.2.1"))
	t.Log(matcher.MatchStr("www.baidu.com"))
	t.Log(matcher.MatchStr("www.google.com"))
}
