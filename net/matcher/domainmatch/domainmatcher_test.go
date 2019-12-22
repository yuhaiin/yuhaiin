package domainmatch

import (
	"testing"
)

func TestDomainMatcher_Search(t *testing.T) {
	root := NewDomainMatcher()
	root.Insert("www.baidu.com", "test_baidu")
	root.Insert("www.google.com", "test_google")
	t.Log(root.Search("www.baidu.com"))
	t.Log(root.Search("www.baidu.cn"))
	t.Log(root.Search("www.google.com"))
	t.Log(root.Search("www.google.cn"))
}

func BenchmarkDomainMatcher_Search(b *testing.B) {
	b.StopTimer()
	root := NewDomainMatcher()
	root.Insert("www.baidu.com", "test_baidu")
	root.Insert("www.baidu.sub.com.cn", "test_baidu")
	root.Insert("www.google.com", "test_google")
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		root.Search("www.baidu.com")
		//root.Search("www.baidu.sub.com.cn.net")
	}
}
