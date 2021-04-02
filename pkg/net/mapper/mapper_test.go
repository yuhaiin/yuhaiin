package mapper

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
)

func TestNewMatcher(t *testing.T) {
	matcher := NewMapper(dns.NewDoH("223.5.5.5", nil).Search)
	matcher.Insert("*.baidu.com", "test_baidu")
	matcher.Insert("10.2.2.1/18", "test_cidr")
	matcher.Insert("*.163.com", "163")
	matcher.Insert("music.126.com", "126")
	matcher.Insert("*.advertising.com", "advertising")
	t.Log(matcher.Search("10.2.2.1"))             // true
	t.Log(matcher.Search("www.baidu.com"))        // true
	t.Log(matcher.Search("passport.baidu.com"))   // true
	t.Log(matcher.Search("tieba.baidu.com"))      // true
	t.Log(matcher.Search("www.google.com"))       // false
	t.Log(matcher.Search("test.music.163.com"))   // true
	t.Log(matcher.Search("guce.advertising.com")) // true
	t.Log(matcher.Search("www.twitter.com"))      // false
	t.Log(matcher.Search("www.facebook.com"))     // false
	t.Log(matcher.Search("127.0.0.1"))            // false
	t.Log(matcher.Search("ff::"))                 // false
}

func BenchmarkMapper(b *testing.B) {
	b.StopTimer()
	matcher := NewMapper(dns.NewDoH("223.5.5.5", nil).Search)
	matcher.Insert("*.baidu.com", "test_baidu")
	matcher.Insert("10.2.2.1/18", "test_cidr")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if i%2 == 1 {
			matcher.Search("www.example.baidu.com")
		} else {
			matcher.Search("10.2.2.1")
		}
	}
}
