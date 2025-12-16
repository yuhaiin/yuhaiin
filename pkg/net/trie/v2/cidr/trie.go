package cidr

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

type Trie[T comparable] struct {
	marks map[T]struct{}
	left  *Trie[T] // bit=0
	right *Trie[T] // bit=1
}

func NewTrie[T comparable]() *Trie[T] {
	return &Trie[T]{marks: make(map[T]struct{})}
}

func (t *Trie[T]) Insert(ip net.IP, maskSize int, mark T) {
	r := t
	bitCount := 0
	for i := range ip {
		for b := byte(128); b != 0 && bitCount < maskSize; b >>= 1 {
			if ip[i]&b != 0 {
				if r.right == nil {
					r.right = NewTrie[T]()
				}
				r = r.right
			} else {
				if r.left == nil {
					r.left = NewTrie[T]()
				}
				r = r.left
			}
			bitCount++
		}
	}
	r.marks[mark] = struct{}{}
}

func (t *Trie[T]) Search(ip net.IP) *set.ImmutableSet[T] {
	r := t
	matched := set.NewSet[T]()

	for i := range ip {
		for b := byte(128); b != 0; b >>= 1 {
			if r == nil {
				return matched.ImmutableSet
			}

			for k := range r.marks {
				matched.Push(k)
			}

			if ip[i]&b != 0 {
				r = r.right
			} else {
				r = r.left
			}
		}
	}
	if r != nil {
		for k := range r.marks {
			matched.Push(k)
		}
	}

	return matched.ImmutableSet
}

func (t *Trie[T]) Remove(ip net.IP, maskSize int, mark T) {
	r := t
	bitCount := 0
	for i := range ip {
		for b := byte(128); b != 0 && bitCount < maskSize; b >>= 1 {
			if r == nil {
				return
			}
			if ip[i]&b != 0 {
				r = r.right
			} else {
				r = r.left
			}
			bitCount++
		}
	}
	if r != nil && r.marks != nil {
		delete(r.marks, mark)
	}
}
