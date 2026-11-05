package cidr

import "net"

type Trie[T any] struct {
	mark  T
	left  *Trie[T] // 0
	right *Trie[T] // 1
	last  bool
}

// Insert adds a CIDR prefix. Existing more-specific prefixes must survive
// inserting or updating a parent prefix.
func (t *Trie[T]) Insert(ip net.IP, maskSize int, mark T) {
	if maskSize < 0 || maskSize > len(ip)*8 {
		return
	}
	node := t
	for depth := 0; depth < maskSize; depth++ {
		var child **Trie[T]
		if ip[depth/8]&(0x80>>uint(depth%8)) != 0 {
			child = &node.right
		} else {
			child = &node.left
		}
		if *child == nil {
			*child = new(Trie[T])
		}
		node = *child
	}
	node.mark = mark
	node.last = true
}

// Search performs longest-prefix matching, including /0 at the root.
func (t *Trie[T]) Search(ip net.IP) (mark T, ok bool) {
	node := t
	mark, ok = node.mark, node.last
	for _, octet := range ip {
		for bit := byte(128); bit != 0; bit >>= 1 {
			if octet&bit != 0 {
				node = node.right
			} else {
				node = node.left
			}
			if node == nil {
				return mark, ok
			}
			if node.last {
				mark, ok = node.mark, true
			}
		}
	}
	return mark, ok
}

func (t *Trie[T]) Remove(ip net.IP) {
	// TODO: implement removal.
}

func NewTrieTree[T any]() Trie[T] { return Trie[T]{} }
