package domain

import "github.com/Asutorufa/yuhaiin/pkg/utils/set"

var (
	_        uint8 = 0
	last     uint8 = 1
	wildcard uint8 = 2
)

type trie[T comparable] struct {
	Value  map[T]struct{}      `json:"value"`
	Child  map[string]*trie[T] `json:"child"`
	Symbol uint8               `json:"symbol"`
}

func (d *trie[T]) child(s string, insert bool) (*trie[T], bool) {
	if insert {
		if d.Child == nil {
			d.Child = make(map[string]*trie[T])
		}
		if d.Child[s] == nil {
			d.Child[s] = &trie[T]{Value: make(map[T]struct{})}
		}
	} else {
		if d.Child == nil {
			return nil, false
		}
	}
	r, ok := d.Child[s]
	return r, ok
}

func insert[T comparable](node *trie[T], z *fqdnReader, mark T) {
	for z.hasNext() {
		if node.Value == nil {
			node.Value = make(map[T]struct{})
		}

		if z.last() && z.str() == "*" {
			node.Symbol = wildcard
			node.Value[mark] = struct{}{}
			break
		}

		node, _ = node.child(z.str(), true)

		if z.last() {
			node.Symbol = last
			node.Value[mark] = struct{}{}
		}

		z.next()
	}
}

func search[T comparable](root *trie[T], domain *fqdnReader) *set.ImmutableSet[T] {
	var res *set.Set[T]
	first, asterisk := true, false

	for domain.hasNext() {
		r, cok := root.child(domain.str(), false)
		switch cok {
		case false:
			if !first {
				if res == nil {
					return set.EmptyImmutableSet[T]()
				}
				return res.Immutable()
			}

			if asterisk {
				domain.next()
				continue
			}

			root, cok = root.child("*", false)
			if !cok {
				if res == nil {
					return set.EmptyImmutableSet[T]()
				}
				return res.Immutable()
			}

			asterisk = true

		case true:
			if len(r.Value) > 0 {
				if res == nil {
					res = set.NewSet[T]()
				}
				for k := range r.Value {
					res.Push(k)
				}
			}

			root = r
			domain.next()
			first = false
		}
	}

	if len(root.Value) > 0 {
		if res == nil {
			res = set.NewSet[T]()
		}
		for k := range root.Value {
			res.Push(k)
		}
	}

	if res == nil {
		return set.EmptyImmutableSet[T]()
	}
	return res.Immutable()
}

func remove[T comparable](node *trie[T], domain *fqdnReader, mark T) {
	nodes := []*trie[T]{node}

	for domain.hasNext() {
		z, ok := node.child(domain.str(), false)
		if !ok {
			if domain.str() == "*" && node.Symbol == wildcard {
				break
			}
			return
		}

		node = z
		nodes = append(nodes, node)
		domain.next()
	}

	if node.Value != nil {
		delete(node.Value, mark)
		if len(node.Value) == 0 {
			node.Symbol = 0
		}
	}

	for i := len(nodes) - 1; i >= 1; i-- {
		parent := nodes[i-1]
		child := nodes[i]
		if len(child.Child) == 0 && len(child.Value) == 0 {
			for k, v := range parent.Child {
				if v == child {
					delete(parent.Child, k)
					break
				}
			}
		} else {
			break
		}
	}
}
