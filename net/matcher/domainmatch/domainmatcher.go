package domainmatch

import (
	"io/ioutil"
	"strings"
)

type node struct {
	isLast bool
	mark   string
	child  map[string]*node
}

type DomainMatcher struct {
	root *node
}

func (domainMatcher *DomainMatcher) Insert(domain, mark string) {
	tmp := domainMatcher.root
	splitTmp := strings.Split(domain, ".")
	for index, n := range splitTmp {
		if index == 0 && n == "www" {
			continue
		}
		if _, ok := tmp.child[n]; !ok {
			tmp.child[n] = &node{
				isLast: false,
				child:  map[string]*node{},
			}
		}
		if index == len(splitTmp)-1 {
			tmp.child[n].isLast = true
			tmp.child[n].mark = mark
		}
		tmp = tmp.child[n]
	}
}

func (domainMatcher *DomainMatcher) InsertWithFile(fileName string) {
	configTemp, _ := ioutil.ReadFile(fileName)
	for _, s := range strings.Split(string(configTemp), "\n") {
		div := strings.Split(s, " ")
		if len(div) < 2 {
			continue
		}
		domainMatcher.Insert(div[0], div[1])
	}
}

func (domainMatcher *DomainMatcher) Search(domain string) (isMatcher bool, mark string) {
	tmp := domainMatcher.root
	isFirst := true
	splitTmp := strings.Split(domain, ".")
	for index, n := range splitTmp {
		_, ok := tmp.child[n]
		if isFirst {
			if !ok {
				continue
			}
		}
		if !ok {
			return false, ""
		}
		if index == len(splitTmp)-1 {
			if tmp.child[n].isLast == true {
				return true, tmp.child[n].mark
			} else {
				return false, ""
			}
		}
		tmp = tmp.child[n]
		isFirst = false
	}
	return false, ""
}

func NewDomainMatcher() *DomainMatcher {
	return &DomainMatcher{root: &node{
		isLast: false,
		child:  map[string]*node{},
	}}
}

func NewDomainMatcherWithFile(filePath string) *DomainMatcher {
	newMatcher := &DomainMatcher{root: &node{
		isLast: false,
		child:  map[string]*node{},
	}}
	newMatcher.InsertWithFile(filePath)
	return newMatcher
}
