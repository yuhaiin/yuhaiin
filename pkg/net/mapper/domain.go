package mapper

import (
	"encoding/json"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

var (
	_        uint8 = 0
	last     uint8 = 1
	wildcard uint8 = 2
)

type domainNode[T any] struct {
	Symbol uint8                     `json:"symbol"`
	Mark   T                         `json:"mark"`
	Child  map[string]*domainNode[T] `json:"child"`
}

func (d *domainNode[T]) child(s string) *domainNode[T] {
	if d.Child == nil {
		d.Child = make(map[string]*domainNode[T])
	}

	if d.Child[s] == nil {
		d.Child[s] = &domainNode[T]{}
	}

	return d.Child[s]
}

func (d *domainNode[T]) childExist(s string) bool { return d.Child != nil && d.Child[s] != nil }

type domainReader struct {
	domain string
	aft    int
	pre    int
}

func newDomainReader(domain string) *domainReader {
	return &domainReader{
		domain: domain,
		aft:    len(domain),
		pre:    strings.LastIndexByte(domain, '.') + 1,
	}
}

func (d *domainReader) hasNext() bool {
	return d.aft >= 0
}

func (d *domainReader) last() bool {
	return d.pre == 0
}

func (d *domainReader) next() bool {
	d.aft = d.pre - 1
	if d.aft < 0 {
		return false
	}
	d.pre = strings.LastIndexByte(d.domain[:d.aft], '.') + 1
	return true
}

func (d *domainReader) reset() {
	d.aft = len(d.domain)
	d.pre = strings.LastIndexByte(d.domain, '.') + 1
}

var valueEmpty = string([]byte{0x03})

func (d *domainReader) str() string {
	if d.pre == d.aft {
		return valueEmpty
	}
	return d.domain[d.pre:d.aft]
}

func s[T any](node *domainNode[T], domain *domainReader) (resp T, ok bool) {
	first, asterisk := true, false

	for domain.hasNext() && node != nil {
		if !node.childExist(domain.str()) {
			if !first {
				return
			}

			if !asterisk {
				node, asterisk = node.child("*"), true
			} else {
				domain.next()
			}

			continue
		}

		node = node.child(domain.str())
		if node.Symbol != 0 {
			if node.Symbol == wildcard {
				resp, ok = node.Mark, true
			}

			if node.Symbol == last && domain.last() {
				return node.Mark, true
			}
		}

		first, _ = false, domain.next()
	}

	return
}

func insert[T any](node *domainNode[T], z *domainReader, mark T) {
	for z.hasNext() {
		if z.last() && z.str() == "*" {
			node.Symbol, node.Mark = wildcard, mark
			break
		}

		node = node.child(z.str())

		if z.last() {
			node.Symbol, node.Mark = last, mark
		}

		z.next()
	}
}

type domain[T any] struct {
	Root         *domainNode[T] `json:"root"`          // for example.com, example.*
	WildcardRoot *domainNode[T] `json:"wildcard_root"` // for *.example.com, *.example.*
}

func (d *domain[T]) Insert(domain string, mark T) {
	if len(domain) == 0 {
		return
	}

	r := newDomainReader(domain)
	if domain[0] == '*' {
		insert(d.WildcardRoot, r, mark)
	} else {
		insert(d.Root, r, mark)
	}
}

func (d *domain[T]) Search(domain proxy.Address) (mark T, ok bool) {
	r := newDomainReader(domain.Hostname())

	mark, ok = s(d.Root, r)
	if ok {
		return
	}

	r.reset()

	return s(d.WildcardRoot, r)
}

func (d *domain[T]) Marshal() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

func (d *domain[T]) Clear() error {
	d.Root = &domainNode[T]{Child: map[string]*domainNode[T]{}}
	d.WildcardRoot = &domainNode[T]{Child: map[string]*domainNode[T]{}}
	return nil
}

func NewDomainMapper[T any]() *domain[T] {
	return &domain[T]{
		Root:         &domainNode[T]{Child: map[string]*domainNode[T]{}},
		WildcardRoot: &domainNode[T]{Child: map[string]*domainNode[T]{}},
	}
}
