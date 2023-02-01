package domain

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

// BenchmarkDomainMatcher_Search-4   	19006478	        71.57 ns/op	      64 B/op	       2 allocs/op
func BenchmarkDomainMatcher_Search(b *testing.B) {
	root := NewDomainMapper[string]()
	root.Insert("*.baidu.com", "test_baidu")
	root.Insert("www.baidu.sub.com.cn", "test_baidu")
	root.Insert("www.google.com", "test_google")

	addr := proxy.ParseAddressPort(0, "www.baidu.sub.com.cn.net", proxy.ParsePort(0))

	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			root.Search(addr)
		}
	})
}

func TestDomainMatcherSearch(t *testing.T) {
	root := NewDomainMapper[string]()
	root.Insert("*.baidu.com", "sub_baidu_test")
	root.Insert("www.baidu.com", "test_baidu")
	root.Insert("last.baidu.*", "test_last_baidu")
	root.Insert("*.baidu.*", "last_sub_baidu_test")
	root.Insert("spo.baidu.com", "test_no_sub_baidu")
	root.Insert("www.google.com", "test_google")
	root.Insert("music.111.com", "1111")
	root.Insert("163.com", "163")
	root.Insert("*.google.com", "google")
	root.Insert("*.dl.google.com", "google_dl")
	root.Insert("api.sec.miui.*", "ad_miui")
	root.Insert("*.miui.com", "miui")

	search := func(s string) string {
		res, _ := root.Search(proxy.ParseAddressPort(0, s, proxy.ParsePort(0)))
		return res
	}
	assert.Equal(t, "test_baidu", search("www.baidu.com"))
	assert.Equal(t, "test_no_sub_baidu", search("spo.baidu.com"))
	assert.Equal(t, "test_last_baidu", search("last.baidu.com.cn"))
	assert.Equal(t, "sub_baidu_test", search("test.baidu.com"))
	assert.Equal(t, "sub_baidu_test", search("test.test2.baidu.com"))
	assert.Equal(t, "last_sub_baidu_test", search("www.baidu.cn"))
	assert.Equal(t, "test_google", search("www.google.com"))
	assert.Equal(t, "", search("www.google.cn"))
	assert.Equal(t, "", search("music.163.com"))
	assert.Equal(t, "163", search("163.com"))
	assert.Equal(t, "google", search("www.x.google.com"))
	assert.Equal(t, "google_dl", search("dl.google.com"))
	assert.Equal(t, "ad_miui", search("api.sec.miui.com"))
}
