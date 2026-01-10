package domain

import (
	"slices"
)

type trie[T comparable] struct {
	Child map[string]*trie[T] `json:"child"`
	Value []T                 `json:"value"`
}

func (d *trie[T]) child(s string, insert bool) (*trie[T], bool) {
	if insert {
		if d.Child == nil {
			d.Child = make(map[string]*trie[T])
		}
		if d.Child[s] == nil {
			d.Child[s] = &trie[T]{}
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
		node, _ = node.child(z.str(), true)
		z.next()
	}

	if !slices.Contains(node.Value, mark) {
		node.Value = append(node.Value, mark)
	}
}

func search[T comparable](root *trie[T], domain *fqdnReader) []T {
	var res []T

	r, ok := root.child(domain.str(), false)
	if ok {
		root = r
		goto _second // match
	}

	// wildcard search

	root, ok = root.child("*", false)
	if !ok {
		return res
	}

	for ; domain.hasNext(); domain.next() {
		if r, ok = root.child(domain.str(), false); ok {
			root = r
			goto _second // wildcard match
		}
	}

	return res

_second:

	for domain.next() {
		if r, ok := root.child("*", false); ok {
			res = append(res, r.Value...)
		}

		root, ok = root.child(domain.str(), false)
		if !ok {
			return res
		}
	}

	res = append(res, root.Value...)
	if r, ok := root.child("*", false); ok {
		res = append(res, r.Value...)
	}

	return res
}

func remove[T comparable](node *trie[T], domain *fqdnReader, mark T) {
	nodes := []*trie[T]{node}

	for domain.hasNext() {
		z, ok := node.child(domain.str(), false)
		if !ok {
			return
		}

		node = z
		nodes = append(nodes, node)
		domain.next()
	}

	if index := slices.Index(node.Value, mark); index != -1 {
		node.Value = append(node.Value[:index], node.Value[index+1:]...)
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
