package mapper

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/stretchr/testify/assert"
)

func TestNewMatcher(t *testing.T) {
	matcher := NewMapper[string](nil)
	matcher.Insert("*.baidu.com", "test_baidu")
	matcher.Insert("10.2.2.1/18", "test_cidr")
	matcher.Insert("*.163.com", "163")
	matcher.Insert("music.126.com", "126")
	matcher.Insert("*.advertising.com", "advertising")

	search := func(s string) interface{} {
		addr, _ := proxy.ParseAddress("", net.JoinHostPort(s, "0"))
		res, _ := matcher.Search(addr)
		return res
	}
	assert.Equal(t, "test_cidr", search("10.2.2.1"))
	assert.Equal(t, "test_baidu", search("www.baidu.com"))
	assert.Equal(t, "test_baidu", search("passport.baidu.com"))
	assert.Equal(t, "test_baidu", search("tieba.baidu.com"))
	assert.Equal(t, "", search("www.google.com"))
	assert.Equal(t, "163", search("test.music.163.com"))
	assert.Equal(t, "advertising", search("guce.advertising.com"))
	assert.Equal(t, "", search("www.twitter.com"))
	assert.Equal(t, "", search("www.facebook.com"))
	assert.Equal(t, "", search("127.0.0.1"))
	assert.Equal(t, "", search("ff::"))
}

func BenchmarkMapper(b *testing.B) {
	b.StopTimer()
	matcher := NewMapper[string](dns.NewDoH("223.5.5.5", "", nil, nil))
	matcher.Insert("*.baidu.com", "test_baidu")
	matcher.Insert("10.2.2.1/18", "test_cidr")
	a1, _ := proxy.ParseAddress("", "www.example.baidu.com:0")
	a2, _ := proxy.ParseAddress("", "10.2.2.1:0")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if i%2 == 1 {
			matcher.Search(a1)
		} else {
			matcher.Search(a2)
		}
	}
}
