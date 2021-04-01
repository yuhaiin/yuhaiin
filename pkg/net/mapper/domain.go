package mapper

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
	for i := len(domain) - 1; i >= 0; i-- {
		if _, ok := root.child[domain[i]]; !ok {
			root.child[domain[i]] = &domainNode{
				child: map[string]*domainNode{},
			}
		}

		if i == 1 && domain[0] == "*" {
			root.child[domain[i]].wildcard = true
			root.child[domain[i]].mark = mark
			root.child[domain[i]].child = make(map[string]*domainNode) // clear child,because this node is last
			break
		}

		if i == 0 {
			root.child[domain[i]].last = true
			root.child[domain[i]].mark = mark
			root.child[domain[i]].child = make(map[string]*domainNode) // clear child,because this node is last
		}

		root = root.child[domain[i]]
	}
}

func (d *Domain) Search(domain string) (mark interface{}, ok bool) {
	domains := strings.Split(domain, ".")
	mark, ok = d.search(d.root, domains, true, false, len(domains)-1)
	if ok {
		return mark, ok
	}
	return d.search(d.wildcardRoot, domains, true, false, len(domains)-1)
}

func (d *Domain) search(root *domainNode, domain []string, first, asterisk bool, index int) (interface{}, bool) {
	if root == nil || index < 0 {
		return nil, false
	}

	if r, ok := root.child[domain[index]]; ok {
		if r.wildcard {
			return r.mark, true
		}
		if r.last && index == 0 {
			return r.mark, true
		}
		return d.search(r, domain, false, asterisk, index-1)
	}

	if !first {
		return nil, false
	}

	if !asterisk {
		return d.search(root.child["*"], domain, first, true, index)
	}

	return d.search(root, domain, first, asterisk, index-1)
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
