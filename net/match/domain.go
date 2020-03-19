package match

import (
	"strings"
)

type domainNode struct {
	isLast bool
	mark   string
	child  map[string]*domainNode
}

type Domain struct {
	root *domainNode
}

func (d *Domain) Insert(domain, mark string) {
	tmp := d.root
	splitTmp := strings.Split(domain, ".")
	for index, n := range splitTmp {
		if index == 0 && n == "www" {
			continue
		}
		if _, ok := tmp.child[n]; !ok {
			tmp.child[n] = &domainNode{
				isLast: false,
				child:  map[string]*domainNode{},
			}
		}
		if index == len(splitTmp)-1 {
			tmp.child[n].isLast = true
			tmp.child[n].mark = mark
		}
		tmp = tmp.child[n]
	}
}

func (d *Domain) Search(domain string) (isMatcher bool, mark string) {
	tmp := d.root
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

func NewDomainMatcher() *Domain {
	return &Domain{root: &domainNode{
		isLast: false,
		child:  map[string]*domainNode{},
	}}
}
