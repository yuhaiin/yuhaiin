package mapper

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
)

// Cidr cidr matcher
type Cidr[T any] struct {
	v4CidrTrie Trie[T]
	v6CidrTrie Trie[T]
	singleTrie Trie[T]
}

// InsetOneCIDR Insert one CIDR to cidr matcher
func (c *Cidr[T]) Insert(cidr string, mark T) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse cidr [%s] failed: %v", cidr, err)
	}
	c.InsertCIDR(ipNet, mark)
	return nil
}

func (c *Cidr[T]) InsertCIDR(ipNet *net.IPNet, mark T) {
	maskSize, _ := ipNet.Mask.Size()
	x := ipNet.IP.To4()
	if x != nil {
		c.v4CidrTrie.Insert(x, maskSize, mark)
	} else {
		c.v6CidrTrie.Insert(ipNet.IP.To16(), maskSize, mark)
	}
}

func (c *Cidr[T]) singleInsert(cidr string, mark T) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse cidr [%s] failed: %v", cidr, err)
	}
	maskSize, _ := ipNet.Mask.Size()
	if len(ipNet.IP) == net.IPv4len {
		maskSize += 96
	}
	c.singleTrie.Insert(ipNet.IP.To16(), maskSize, mark)
	return nil
}

func (c *Cidr[T]) singleSearch(ip string) (mark T, ok bool) {
	return c.singleTrie.Search(net.ParseIP(ip).To16())
}

// MatchWithTrie match ip with trie
func (c *Cidr[T]) Search(ip string) (mark T, ok bool) {
	iP := net.ParseIP(ip)
	if iP == nil {
		return mark, false
	}
	return c.SearchIP(iP)
}

func (c *Cidr[T]) SearchIP(ip net.IP) (mark T, ok bool) {
	if x := ip.To4(); x != nil {
		return c.v4CidrTrie.Search(x)
	} else {
		return c.v6CidrTrie.Search(ip.To16())
	}
}

// NewCidrMatchWithTrie <--
func NewCidrMapper[T any]() *Cidr[T] {
	cidrMapper := new(Cidr[T])
	cidrMapper.v4CidrTrie = NewTrieTree[T]()
	cidrMapper.v6CidrTrie = NewTrieTree[T]()
	cidrMapper.singleTrie = NewTrieTree[T]()
	return cidrMapper
}

/*******************************
	CIDR TRIE
********************************/
type Trie[T any] struct {
	mark  T
	last  bool
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
		log.Printf("0 ")
	}
	if node.right != nil {
		t.PrintTree(node.right)
		log.Printf("1 ")
	}
}

// NewTrieTree create a new trie tree
func NewTrieTree[T any]() Trie[T] {
	return Trie[T]{}
}

func ipv4toInt(ip net.IP) string {
	return fmt.Sprintf("%032b", binary.BigEndian.Uint32(ip)) // there ip is ip.To4()
}

func ipv4toInt2(ip net.IP) []byte {
	s := make([]byte, 0, 32)
	for i := range ip {
		for b := byte(128); b != 0; b = b >> 1 {
			if ip[i]&b != 0 {
				s = append(s, 1)
			} else {
				s = append(s, 0)
			}
		}
	}
	return s
}

func ipv6toInt(ip net.IP) string {
	// from http://golang.org/pkg/net/#pkg-constants
	// IPv6len = 16
	return fmt.Sprintf("%0128b", big.NewInt(0).SetBytes(ip)) // there ip is ip.To16()
}

func ipv6toInt2(ip net.IP) []byte {
	s := make([]byte, 0, 128)
	for i := range ip {
		for b := byte(128); b != 0; b = b >> 1 {
			if ip[i]&b != 0 {
				s = append(s, 1)
			} else {
				s = append(s, 0)
			}
		}
	}
	return s
}
