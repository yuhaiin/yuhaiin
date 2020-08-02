package match

import (
	"strings"
)

type domainNode struct {
	isLast    bool
	subdomain bool
	mark      interface{}
	child     map[string]*domainNode
}

type Domain struct {
	root *domainNode
}

func (d *Domain) InsertFlip(domain string, mark interface{}) {
	tmp := d.root
	domainDiv := strings.Split(domain, ".")
	for index := len(domainDiv) - 1; index >= 0; index-- {
		if _, ok := tmp.child[domainDiv[index]]; !ok {
			tmp.child[domainDiv[index]] = &domainNode{
				child: map[string]*domainNode{},
			}
		}

		tmp.isLast = false
		tmp.subdomain = false

		if index == 1 && domainDiv[0] == "*" {
			tmp.child[domainDiv[index]].subdomain = true
			tmp.child[domainDiv[index]].mark = mark
			tmp.child[domainDiv[index]].child = make(map[string]*domainNode) // clear child,because this node is last
			break
		}

		if index == 0 { // check already exist or last
			tmp.child[domainDiv[index]].isLast = true
			tmp.child[domainDiv[index]].mark = mark
			tmp.child[domainDiv[index]].child = make(map[string]*domainNode) // clear child,because this node is last
		}
		tmp = tmp.child[domainDiv[index]]
	}
}

func (d *Domain) SearchFlip(domain string) (isMatcher bool, mark interface{}) {
	root := d.root
	domainDiv := strings.Split(domain, ".")
	for index := len(domainDiv) - 1; index >= 0; index-- {
		_, ok := root.child[domainDiv[index]] // use index to get data quicker than new var
		if !ok {
			//log.Println("!ok", domainDiv[index])
			return false, nil
		}

		if root.child[domainDiv[index]].subdomain == true {
			return true, root.child[domainDiv[index]].mark
		}

		if index == 0 && root.child[domainDiv[index]].isLast == true {
			return true, root.child[domainDiv[index]].mark
		}

		root = root.child[domainDiv[index]]
	}
	return false, nil
}

func NewDomainMatch() *Domain {
	return &Domain{root: &domainNode{
		isLast:    false,
		subdomain: false,
		child:     map[string]*domainNode{},
	}}
}
