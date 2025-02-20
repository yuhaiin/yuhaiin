package trie

import (
	"context"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestNewMatcher(t *testing.T) {
	matcher := NewTrie[string]()
	matcher.Insert("*.baidu.com", "test_baidu")
	matcher.Insert("10.2.2.1/18", "test_cidr")
	matcher.Insert("*.163.com", "163")
	matcher.Insert("music.126.com", "126")
	matcher.Insert("*.advertising.com", "advertising")
	matcher.Insert("api.sec.miui.*", "ad_miui")

	search := func(s string) string {
		addr, _ := netapi.ParseAddress("", net.JoinHostPort(s, "0"))
		res, _ := matcher.Search(context.TODO(), addr)
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
	assert.Equal(t, "ad_miui", search("api.sec.miui.com"))
}

func BenchmarkMapper(b *testing.B) {

	matcher := NewTrie[string]()
	matcher.Insert("*.baidu.com", "test_baidu")
	matcher.Insert("10.2.2.1/18", "test_cidr")
	a1, _ := netapi.ParseAddress("", "www.example.baidu.com:0")
	a2, _ := netapi.ParseAddress("", "10.2.2.1:0")

	for i := 0; b.Loop(); i++ {
		if i%2 == 1 {
			matcher.Search(context.TODO(), a1)
		} else {
			matcher.Search(context.TODO(), a2)
		}
	}
}
