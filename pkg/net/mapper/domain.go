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

type domainStr struct {
	domain string
	aft    int
	pre    int
}

func newDomainStr(domain string) *domainStr {
	return &domainStr{
		domain: domain,
		aft:    len(domain),
		pre:    strings.LastIndexByte(domain, '.') + 1,
	}
}

func (d *domainStr) hasNext() bool {
	return d.aft >= 0
}

func (d *domainStr) last() bool {
	return d.pre == 0
}

func (d *domainStr) next() bool {
	d.aft = d.pre - 1
	if d.aft < 0 {
		return false
	}
	d.pre = strings.LastIndexByte(d.domain[:d.aft], '.') + 1
	return true
}

func (d *domainStr) str() string {
	return d.domain[d.pre:d.aft]
}

func s(root *domainNode, domain string) (resp interface{}, ok bool) {
	s := root
	z := newDomainStr(domain)
	first, asterisk := true, false

	for {
		if !z.hasNext() || s == nil {
			return
		}

		if r, ok := s.child[z.str()]; ok {
			if r.symbol == wildcard {
				resp, ok = r.mark, true
			}

			if r.symbol == last && z.last() {
				return r.mark, true
			}

			s, first, _ = r, false, z.next()
			continue
		}

		if !first {
			return
		}

		if !asterisk {
			s, asterisk = root.child["*"], true
		} else {
			z.next()
		}
	}
}

func insert(root *domainNode, domain string, mark interface{}) {
	z := newDomainStr(domain)
	for z.hasNext() {
		if z.last() && domain[0] == '*' {
			root.symbol = wildcard
			root.mark = mark
			break
		}

		if root.child == nil {
			root.child = make(map[string]*domainNode)
		}

		if root.child[z.str()] == nil {
			root.child[z.str()] = &domainNode{}
		}

		root = root.child[z.str()]

		if z.last() {
			root.symbol = last
			root.mark = mark
		}

		z.next()
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
	mark, ok = s(d.root, domain)
	if ok {
		return
	}
	return s(d.wildcardRoot, domain)
}

func NewDomainMapper() *domain {
	return &domain{
		root:         &domainNode{child: map[string]*domainNode{}},
		wildcardRoot: &domainNode{child: map[string]*domainNode{}},
	}
}
