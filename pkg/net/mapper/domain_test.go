package mapper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// BenchmarkDomainMatcher_Search-4   	20780998	        58.13 ns/op	       0 B/op	       0 allocs/op
func BenchmarkDomainMatcher_Search(b *testing.B) {
	root := NewDomainMapper[string]()
	root.Insert("*.baidu.com", "test_baidu")
	root.Insert("www.baidu.sub.com.cn", "test_baidu")
	root.Insert("www.google.com", "test_google")

	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			root.Search("www.baidu.sub.com.cn.net")
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

	search := func(s string) interface{} {
		res, _ := root.Search(s)
		return res
	}
	assert.Equal(t, "test_baidu", search("www.baidu.com"))
	assert.Equal(t, "test_no_sub_baidu", search("spo.baidu.com"))
	assert.Equal(t, "test_last_baidu", search("last.baidu.com.cn"))
	assert.Equal(t, "sub_baidu_test", search("test.baidu.com"))
	assert.Equal(t, "sub_baidu_test", search("test.test2.baidu.com"))
	assert.Equal(t, "last_sub_baidu_test", search("www.baidu.cn"))
	assert.Equal(t, "test_google", search("www.google.com"))
	assert.Equal(t, nil, search("www.google.cn"))
	assert.Equal(t, nil, search("music.163.com"))
	assert.Equal(t, "163", search("163.com"))
	assert.Equal(t, "google", search("www.x.google.com"))
	assert.Equal(t, "google_dl", search("dl.google.com"))
}

func TestGetIndex(t *testing.T) {
	t.Log(getIndex("google"))
	t.Log(getIndex("lllzczfdvriadaoPDCMDFSOFSADOAMDFOSOCMSOFKEORFMSKFMSOEFSMCNSDFSOFPSCSMDKFNSOdsdsfdrefsdacadasfdferewbnmhjhDswdwecdlkcmskdfosfmdksofewnrsmcxzcmosdfsmdfweoprqnldafadv-sdadkma231oem23i1o3nq2w1odadasdnwieni232hioeoqbo3i12bwqeioqwebqi21313h1oh23bqek321o3endaowe"))
}

func TestDomain2MatcherSearch(t *testing.T) {
	root := NewDomain2Mapper()
	root.Insert("*.baidu.com", "sub_baidu_test")
	root.Insert("www.baidu.com", "test_baidu")
	root.Insert("last.baidu.*", "test_last_baidu")
	root.Insert("*.baidu.*", "last_sub_baidu_test")
	root.Insert("spo.baidu.com", "test_no_sub_baidu")
	root.Insert("www.google.com", "test_google")
	root.Insert("music.111.com", "1111")
	root.Insert("163.com", "163")

	search := func(s string) interface{} {
		res, _ := root.Search(s)
		return res
	}
	assert.Equal(t, "test_baidu", search("www.baidu.com"))
	assert.Equal(t, "test_no_sub_baidu", search("spo.baidu.com"))
	assert.Equal(t, "test_last_baidu", search("last.baidu.com.cn"))
	assert.Equal(t, "sub_baidu_test", search("test.baidu.com"))
	assert.Equal(t, "sub_baidu_test", search("test.test2.baidu.com"))
	assert.Equal(t, "last_sub_baidu_test", search("www.baidu.cn"))
	assert.Equal(t, "test_google", search("www.google.com"))
	assert.Equal(t, nil, search("www.google.cn"))
	assert.Equal(t, nil, search("music.163.com"))
	assert.Equal(t, "163", search("163.com"))
}
