package mapper

import (
	"strings"
)

var (
	_        = 0
	last     = 1
	wildcard = 2
)

type domainNode struct {
	symbol int
	mark   interface{}
	child  map[string]*domainNode
}

func search(root *domainNode, domain string) (interface{}, bool) {
	return searchDFS(root, domain, true, false, len(domain))
}

func searchDFS(root *domainNode, domain string, first, asterisk bool, aft int) (interface{}, bool) {
	if root == nil || root.child == nil || aft < 0 {
		return nil, false
	}

	pre := strings.LastIndexByte(domain[:aft], '.') + 1

	if r, ok := root.child[domain[pre:aft]]; ok {
		if r.symbol == wildcard {
			return r.mark, true
		}
		if r.symbol == last && pre == 0 {
			return r.mark, true
		}
		return searchDFS(r, domain, false, asterisk, pre-1)
	}

	if !first {
		return nil, false
	}

	if !asterisk {
		return searchDFS(root.child["*"], domain, first, true, aft)
	}

	return searchDFS(root, domain, first, asterisk, pre-1)
}

func insert(root *domainNode, domain string, mark interface{}) {
	aft := len(domain)
	var pre int
	for aft >= 0 {
		pre = strings.LastIndexByte(domain[:aft], '.') + 1

		if pre == 0 && domain[0] == '*' {
			root.symbol = wildcard
			root.mark = mark
			root.child = nil
			break
		}

		if root.child == nil {
			root.child = map[string]*domainNode{}
		}
		if root.child[domain[pre:aft]] == nil {
			root.child[domain[pre:aft]] = &domainNode{child: make(map[string]*domainNode)}
		}

		root = root.child[domain[pre:aft]]

		if pre == 0 {
			root.symbol = last
			root.mark = mark
			root.child = nil
		}

		aft = pre - 1
	}
}

type domain struct {
	root         *domainNode // for example.com, example.*
	wildcardRoot *domainNode // for *.example.com, *.example.*
}

func (d *domain) Insert(domain string, mark interface{}) {
	if len(domain) == 0 {
		return
	}

	if domain[0] == '*' {
		insert(d.wildcardRoot, domain, mark)
	} else {
		insert(d.root, domain, mark)
	}
}

func (d *domain) Search(domain string) (mark interface{}, ok bool) {
	mark, ok = search(d.root, domain)
	if ok {
		return
	}
	return search(d.wildcardRoot, domain)
}

func NewDomainMapper() *domain {
	return &domain{
		root:         &domainNode{child: map[string]*domainNode{}},
		wildcardRoot: &domainNode{child: map[string]*domainNode{}},
	}
}
