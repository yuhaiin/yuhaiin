package domainmatch

import "testing"

func TestDomainMatcher_Search(t *testing.T) {
	root := NewDomainMatcher()
	root.Insert("www.baidu.com")
	root.Insert("www.google.com")
	t.Log(root.Search("www.baidu.com"))
	t.Log(root.Search("www.baidu.cn"))
}
