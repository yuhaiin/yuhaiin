package match

import (
	"log"
	"strings"
	"testing"
)

// 165 ns/op
func BenchmarkDomainMatcher_Search(b *testing.B) {
	b.StopTimer()
	root := NewDomainMapper()
	root.Insert("*.baidu.com", "test_baidu")
	root.Insert("www.baidu.sub.com.cn", "test_baidu")
	root.Insert("www.google.com", "test_google")
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		root.Search("www.baidu.com")
		//root.Search("www.baidu.sub.com.cn.net")
	}
}

func TestDomain_Insert(t *testing.T) {
	x := strings.Split("music.163.com", ".")
	for index := range x {
		log.Println(x[index], index, len(x))
	}
}

func TestDomainMatcher_SearchFlip(t *testing.T) {
	root := NewDomainMapper()
	root.Insert("*.baidu.com", "sub_baidu_test")
	root.Insert("www.baidu.com", "test_baidu")
	root.Insert("last.baidu.*", "test_last_baidu")
	root.Insert("*.baidu.*", "last_sub_baidu_test")
	root.Insert("www.google.com", "test_google")
	root.Insert("music.111.com", "1111")
	root.Insert("163.com", "163")
	t.Log(root.Search("www.baidu.com"))
	t.Log(root.Search("last.baidu.com.cn"))
	t.Log(root.Search("test.baidu.com"))
	t.Log(root.Search("test.test2.baidu.com"))
	t.Log(root.Search("www.baidu.cn"))
	t.Log(root.Search("www.google.com"))
	t.Log(root.Search("www.google.cn"))
	t.Log(root.Search("music.163.com"))
	t.Log(root.Search("163.com"))
}
