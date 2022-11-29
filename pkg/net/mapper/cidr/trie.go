package cidr

import (
	"math"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

type Trie[T any] struct {
	last  bool
	mark  T
	left  *Trie[T] // 0
	right *Trie[T] // 1
}

// Insert insert node to tree
func (t *Trie[T]) Insert(ip net.IP, maskSize int, mark T) {
	r := t
	for i := range ip {
		for b := byte(128); b != 0; b = b >> 1 {
			if ip[i]&b != 0 {
				if r.right == nil {
					r.right = new(Trie[T])
				}
				r = r.right
			} else {
				if r.left == nil {
					r.left = new(Trie[T])
				}
				r = r.left
			}

			if i*8+int(math.Log2(float64(128/b)))+1 == maskSize {
				r.mark = mark
				r.last = true
				r.left = new(Trie[T])
				r.right = new(Trie[T])
				return
			}
		}
	}
}

// Search search from trie tree
func (t *Trie[T]) Search(ip net.IP) (mark T, ok bool) {
	r := t
out:
	for i := range ip {
		for b := byte(128); b != 0; b = b >> 1 {
			if ip[i]&b != 0 { // bit = 1
				r = r.right
			} else { // bit = 0
				r = r.left
			}
			if r == nil {
				break out
			}
			if r.last {
				mark, ok = r.mark, true
			}
		}
	}
	return
}

// PrintTree print this tree
func (t *Trie[T]) PrintTree(node *Trie[T]) {
	if node.left != nil {
		t.PrintTree(node.left)
		log.Debugln("0 ")
	}
	if node.right != nil {
		t.PrintTree(node.right)
		log.Debugln("1 ")
	}
}

// NewTrieTree create a new trie tree
func NewTrieTree[T any]() Trie[T] {
	return Trie[T]{}
}
