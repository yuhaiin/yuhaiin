package cidr

import (
	"net"
	"slices"
)

type Trie[T comparable] struct {
	marks []T
	left  *Trie[T] // bit=0
	right *Trie[T] // bit=1
}

func NewTrie[T comparable]() *Trie[T] {
	return &Trie[T]{}
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

	if !slices.Contains(r.marks, mark) {
		r.marks = append(r.marks, mark)
	}
}

func (t *Trie[T]) Search(ip net.IP) []T {
	r := t
	var matched []T

	for i := range ip {
		for b := byte(128); b != 0; b >>= 1 {
			if r == nil {
				return matched
			}

			matched = append(matched, r.marks...)

			if ip[i]&b != 0 {
				r = r.right
			} else {
				r = r.left
			}
		}
	}
	if r != nil {
		matched = append(matched, r.marks...)
	}

	return matched
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
		index := slices.Index(r.marks, mark)
		if index != -1 {
			r.marks = append(r.marks[:index], r.marks[index+1:]...)
		}
	}
}
