package domainmatch

import (
	"fmt"
	"strings"
)

type node struct {
	isLast bool
	child  map[string]*node
}

type DomainMatcher struct {
	root *node
}

func (domainMatcher *DomainMatcher) Insert(domain string) {
	tmp := domainMatcher.root
	splitTmp := strings.Split(domain, ".")
	for index, n := range splitTmp {
		if _, ok := tmp.child[n]; !ok {
			tmp.child[n] = &node{
				isLast: false,
				child:  map[string]*node{},
			}
		}
		if index == len(splitTmp)-1 {
			tmp.child[n].isLast = true
		}
		tmp = tmp.child[n]
	}
}

func (domainMatcher *DomainMatcher) Search(domain string) bool {
	tmp := domainMatcher.root
	splitTmp := strings.Split(domain, ".")
	for index, n := range splitTmp {
		if _, ok := tmp.child[n]; !ok {
			return false
		}
		if index == len(splitTmp)-1 {
			return tmp.child[n].isLast == true
		}
		tmp = tmp.child[n]
	}
	return false
}

func NewDomainMatcher() *DomainMatcher {
	return &DomainMatcher{root: &node{
		isLast: false,
		child:  map[string]*node{},
	}}
}

func _() {
	root := NewDomainMatcher()
	root.Insert("www.baidu.com")
	root.Insert("www.google.com")
	fmt.Println(root.Search("www.baidu.com"))
	fmt.Println(root.Search("www.baidu.cn"))
}
