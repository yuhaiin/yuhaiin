package match

import (
	"strings"
)

type domainNode struct {
	last     bool
	wildcard bool
	mark     interface{}
	child    map[string]*domainNode
}

type Domain struct {
	root         *domainNode // for example.com, example.*
	wildcardRoot *domainNode // for *.example.com, *.example.*
}

func (d *Domain) InsertFlip(domain string, mark interface{}) {
	domainDiv := strings.Split(domain, ".")
	if len(domainDiv) == 0 {
		return
	}
	if domainDiv[0] == "*" {
		d.insert(d.wildcardRoot, mark, domainDiv)
		return
	}
	d.insert(d.root, mark, domainDiv)
}

func (d *Domain) insert(root *domainNode, mark interface{}, domain []string) {
	for index := len(domain) - 1; index >= 0; index-- {
		if _, ok := root.child[domain[index]]; !ok {
			root.child[domain[index]] = &domainNode{
				child: map[string]*domainNode{},
			}
		}

		if index == 1 && domain[0] == "*" {
			root.child[domain[index]].wildcard = true
			root.child[domain[index]].mark = mark
			root.child[domain[index]].child = make(map[string]*domainNode) // clear child,because this node is last
			break
		}

		if index == 0 {
			root.child[domain[index]].last = true
			root.child[domain[index]].mark = mark
			root.child[domain[index]].child = make(map[string]*domainNode) // clear child,because this node is last
		}

		root = root.child[domain[index]]
	}
}

func (d *Domain) SearchFlip(domain string) (isMatcher bool, mark interface{}) {
	domainDiv := strings.Split(domain, ".")
	isMatcher, mark = d.search(d.root, domainDiv)
	if isMatcher {
		return isMatcher, mark
	}
	return d.search(d.wildcardRoot, domainDiv)
}

func (d *Domain) search(root *domainNode, domain []string) (bool, interface{}) {
	first, asterisk := true, false
	for index := len(domain) - 1; index >= 0; index-- {
	_retry:
		_, ok := root.child[domain[index]] // use index to get data quicker than new var
		if ok {
			first = false
			if root.child[domain[index]].wildcard == true || (root.child[domain[index]].last == true && index == 0) {
				return true, root.child[domain[index]].mark
			}
			root = root.child[domain[index]]
			continue
		}

		if !first {
			break
		}

		if asterisk {
			continue
		}

		root = root.child["*"]
		if root == nil {
			break
		}
		asterisk = true
		goto _retry
	}

	return false, nil
}

func NewDomainMatch() *Domain {
	return &Domain{
		root: &domainNode{
			child: map[string]*domainNode{},
		},
		wildcardRoot: &domainNode{
			child: map[string]*domainNode{},
		},
	}
}
