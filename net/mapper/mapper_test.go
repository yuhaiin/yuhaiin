package mapper

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/net/dns"
)

func TestNewMatcher(t *testing.T) {
	//dnsFunc := func(domain string) (IP []net.IP, s error) {
	//	return dns.DNS("119.29.29.29:53", domain)
	//}
	matcher := NewMapper(dns.NewDOH("223.5.5.5", nil).Search)
	if err := matcher.Insert("*.baidu.com", "test_baidu"); err != nil {
		t.Error(err)
	}
	if err := matcher.Insert("10.2.2.1/18", "test_cidr"); err != nil {
		t.Error(err)
	}
	if err := matcher.Insert("*.163.com", "163"); err != nil {
		t.Error(err)
	}
	if err := matcher.Insert("music.126.com", "126"); err != nil {
		t.Error(err)
	}
	if err := matcher.Insert("*.advertising.com", "advertising"); err != nil {
		t.Error(err)
	}
	t.Log(matcher.Search("10.2.2.1"))
	t.Log(matcher.Search("www.baidu.com"))
	t.Log(matcher.Search("passport.baidu.com"))
	t.Log(matcher.Search("tieba.baidu.com"))
	t.Log(matcher.Search("www.google.com"))
	t.Log(matcher.Search("test.music.163.com"))
	t.Log(matcher.Search("guce.advertising.com"))
	t.Log(matcher.Search("www.twitter.com"))
	t.Log(matcher.Search("www.facebook.com"))
}
