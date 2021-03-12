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

func (d *Domain) Insert(domain string, mark interface{}) {
	domains := strings.Split(domain, ".")
	if len(domains) == 0 {
		return
	}
	if domains[0] == "*" {
		d.insert(d.wildcardRoot, mark, domains)
		return
	}
	d.insert(d.root, mark, domains)
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

func (d *Domain) Search(domain string) (ok bool, mark interface{}) {
	domains := strings.Split(domain, ".")
	ok, mark = d.search(d.root, domains)
	if ok {
		return ok, mark
	}
	return d.search(d.wildcardRoot, domains)
}

func (d *Domain) search(root *domainNode, domain []string) (bool, interface{}) {
	first, asterisk := true, false
	for i := len(domain) - 1; i >= 0; i-- {
	_retry:
		_, ok := root.child[domain[i]] // use index to get data quicker than new var
		if ok {
			first = false
			if root.child[domain[i]].wildcard == true {
				return true, root.child[domain[i]].mark
			}
			if root.child[domain[i]].last == true && i == 0 {
				return true, root.child[domain[i]].mark
			}
			root = root.child[domain[i]]
			continue
		}

		if !first {
			break
		}

		if !asterisk {
			root = root.child["*"]
			if root == nil {
				break
			}
			asterisk = true
			goto _retry
		}
	}

	return false, nil
}

func NewDomainMapper() *Domain {
	return &Domain{
		root: &domainNode{
			child: map[string]*domainNode{},
		},
		wildcardRoot: &domainNode{
			child: map[string]*domainNode{},
		},
	}
}
