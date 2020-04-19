package match

import (
	"github.com/Asutorufa/yuhaiin/net/dns"
	"net"
	"testing"
)

func TestNewMatcher(t *testing.T) {
	dnsFunc := func(domain string) (IP []net.IP, s bool) {
		IP, s, _ = dns.MDNS("119.29.29.29:53", domain)
		return
	}
	matcher, _ := NewMatch(dnsFunc, "")
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
	dnsFunc := func(domain string) (IP []net.IP, s bool) {
		IP, s, _ = dns.MDNS("119.29.29.29:53", domain)
		return
	}
	matcher, err := NewMatch(dnsFunc, "../../rule/rule.config")
	if err != nil {
		t.Error(err)
	}
	t.Log(matcher.Search("10.2.2.1"))
	t.Log(matcher.Search("www.baidu.com"))
	t.Log(matcher.Search("www.google.com"))
}
