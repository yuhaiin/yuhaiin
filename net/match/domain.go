package match

import (
	"strings"
)

type domainNode struct {
	isLast bool
	mark   interface{}
	child  map[string]*domainNode
}

type Domain struct {
	root *domainNode
}

func (d *Domain) Insert(domain string, mark interface{}) {
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

func (d *Domain) Search(domain string) (isMatcher bool, mark interface{}) {
	root := d.root
	first, domainDiv := true, strings.Split(domain, ".")
	for index := range domainDiv {
		_, ok := root.child[domainDiv[index]]

		if first && !ok {
			continue
		}

		if !ok {
			return false, nil
		}

		if index == len(domainDiv)-1 {
			if root.child[domainDiv[index]].isLast == true {
				return true, root.child[domainDiv[index]].mark
			}
			return false, nil
		}

		root = root.child[domainDiv[index]]
		first = false
	}
	return false, nil
}

func NewDomainMatch() *Domain {
	return &Domain{root: &domainNode{
		isLast: false,
		child:  map[string]*domainNode{},
	}}
}
