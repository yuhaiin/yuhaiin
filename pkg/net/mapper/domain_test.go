package mapper

import (
	"log"
	"strings"
	"testing"
)

// BenchmarkDomainMatcher_Search-4   	20780998	        58.13 ns/op	       0 B/op	       0 allocs/op
func BenchmarkDomainMatcher_Search(b *testing.B) {
	b.StopTimer()
	root := NewDomainMapper()
	root.Insert("*.baidu.com", "test_baidu")
	root.Insert("www.baidu.sub.com.cn", "test_baidu")
	root.Insert("www.google.com", "test_google")
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		if n%2 == 0 {
			root.Search("www.baidu.com")
		} else {
			root.Search("www.baidu.sub.com.cn.net")
		}
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
	root.Insert("spo.baidu.com", "test_no_sub_baidu")
	root.Insert("www.google.com", "test_google")
	root.Insert("music.111.com", "1111")
	root.Insert("163.com", "163")
	t.Log(root.Search("www.baidu.com"))        // true
	t.Log(root.Search("spo.baidu.com"))        // true
	t.Log(root.Search("last.baidu.com.cn"))    // true
	t.Log(root.Search("test.baidu.com"))       // true
	t.Log(root.Search("test.test2.baidu.com")) // true
	t.Log(root.Search("www.baidu.cn"))         // true
	t.Log(root.Search("www.google.com"))       // true
	t.Log(root.Search("www.google.cn"))        // false
	t.Log(root.Search("music.163.com"))        // false
	t.Log(root.Search("163.com"))              // true
}
