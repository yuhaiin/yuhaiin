package match

import (
	"log"
	"strings"
	"testing"
)

// 165 ns/op
func BenchmarkDomainMatcher_Search(b *testing.B) {
	b.StopTimer()
	root := NewDomainMatch()
	root.InsertFlip("www.baidu.com", "test_baidu")
	root.InsertFlip("www.baidu.sub.com.cn", "test_baidu")
	root.InsertFlip("www.google.com", "test_google")
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		root.SearchFlip("www.baidu.com")
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
	root := NewDomainMatch()
	root.InsertFlip("www.baidu.com", "test_baidu")
	root.InsertFlip("www.google.com", "test_google")
	root.InsertFlip("music.111.com", "1111")
	root.InsertFlip("163.com", "163")
	t.Log(root.SearchFlip("www.baidu.com"))
	t.Log(root.SearchFlip("www.baidu.cn"))
	t.Log(root.SearchFlip("www.google.com"))
	t.Log(root.SearchFlip("www.google.cn"))
	t.Log(root.SearchFlip("music.163.com"))
	t.Log(root.SearchFlip("163.com"))
}
