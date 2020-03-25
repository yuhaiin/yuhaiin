package match

import (
	"github.com/Asutorufa/yuhaiin/net/dns"
	"testing"
)

func TestNewMatcher(t *testing.T) {
	dnsFunc := func(domain string) ([]string, bool) {
		return dns.DNS("119.29.29.29:53", domain)
	}
	matcher := NewMatch(dnsFunc)
	if err := matcher.Insert("www.baidu.com", "test_baidu"); err != nil {
		t.Error(err)
	}
	if err := matcher.Insert("10.2.2.1/18", "test_cidr"); err != nil {
		t.Error(err)
	}
	t.Log(matcher.Search("10.2.2.1"))
	t.Log(matcher.Search("www.baidu.com"))
	t.Log(matcher.Search("www.google.com"))
}

func TestNewMatcherWithFile(t *testing.T) {
	dnsFunc := func(domain string) ([]string, bool) {
		return dns.DNS("119.29.29.29:53", domain)
	}
	matcher, err := NewMatchWithFile(dnsFunc, "../../rule/rule.config")
	if err != nil {
		t.Error(err)
	}
	t.Log(matcher.Search("10.2.2.1"))
	t.Log(matcher.Search("www.baidu.com"))
	t.Log(matcher.Search("www.google.com"))
}
