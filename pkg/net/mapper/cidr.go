package mapper

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
)

// Cidr cidr matcher
type Cidr struct {
	v4CidrTrie Trie
	v6CidrTrie Trie
	singleTrie Trie
}

// InsetOneCIDR Insert one CIDR to cidr matcher
func (c *Cidr) Insert(cidr string, mark interface{}) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse cidr [%s] failed: %v", cidr, err)
	}
	c.InsertCIDR(ipNet, mark)
	return nil
}

func (c *Cidr) InsertCIDR(ipNet *net.IPNet, mark interface{}) {
	maskSize, _ := ipNet.Mask.Size()
	x := ipNet.IP.To4()
	if x != nil {
		c.v4CidrTrie.Insert(x, maskSize, mark)
	} else {
		c.v6CidrTrie.Insert(ipNet.IP.To16(), maskSize, mark)
	}
}

func (c *Cidr) singleInsert(cidr string, mark interface{}) error {
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

func (c *Cidr) singleSearch(ip string) (mark interface{}, ok bool) {
	return c.singleTrie.Search(net.ParseIP(ip).To16())
}

// MatchWithTrie match ip with trie
func (c *Cidr) Search(ip string) (mark interface{}, ok bool) {
	iP := net.ParseIP(ip)
	if iP == nil {
		return nil, false
	}
	return c.SearchIP(iP)
}

func (c *Cidr) SearchIP(ip net.IP) (mark interface{}, ok bool) {
	if x := ip.To4(); x != nil {
		return c.v4CidrTrie.Search(x)
	} else {
		return c.v6CidrTrie.Search(ip.To16())
	}
}

// NewCidrMatchWithTrie <--
func NewCidrMapper() *Cidr {
	cidrMapper := new(Cidr)
	cidrMapper.v4CidrTrie = NewTrieTree()
	cidrMapper.v6CidrTrie = NewTrieTree()
	cidrMapper.singleTrie = NewTrieTree()
	return cidrMapper
}

/*******************************
	CIDR TRIE
********************************/
type Trie struct {
	isLast bool
	mark   interface{}
	left   *Trie // 0
	right  *Trie // 1
}

// Insert insert node to tree
func (t *Trie) Insert(ip net.IP, maskSize int, mark interface{}) {
	r := t
	for i := range ip {
		for b := byte(128); b != 0; b = b >> 1 {
			if ip[i]&b != 0 {
				if r.right == nil {
					r.right = new(Trie)
				}
				r = r.right
			} else {
				if r.left == nil {
					r.left = new(Trie)
				}
				r = r.left
			}

			if r.isLast || i*8+int(math.Log2(float64(128/b)))+1 == maskSize {
				r.isLast = true
				r.mark = mark
				r.left = new(Trie)
				r.right = new(Trie)
				return
			}
		}
	}
}

// Search search from trie tree
func (t *Trie) Search(ip net.IP) (mark interface{}, ok bool) {
	r := t
	for i := range ip {
		for b := byte(128); b != 0; b = b >> 1 {
			if ip[i]&b != 0 { // bit = 1
				r = r.right
			} else { // bit = 0
				r = r.left
			}
			if r == nil {
				return nil, false
			}
			if r.isLast {
				return r.mark, true
			}
		}
	}
	return nil, false
}

// PrintTree print this tree
func (t *Trie) PrintTree(node *Trie) {
	if node.left != nil {
		t.PrintTree(node.left)
		log.Printf("0 ")
	}
	if node.right != nil {
		t.PrintTree(node.right)
		log.Printf("1 ")
	}
}

func (t *Trie) Print() {
	type p struct {
		c *Trie
		s string
	}
	x := list.List{}
	x.PushBack(&p{
		c: t,
		s: "",
	})

	for x.Len() != 0 {
		y := x.Front()
		z := y.Value.(*p)
		fmt.Printf("%v ", z.s)
		x.Remove(y)

		if z.c.left != nil {
			x.PushBack(&p{
				c: z.c.left,
				s: "0",
			})
		}

		if z.c.right != nil {
			x.PushBack(&p{
				c: z.c.right,
				s: "1",
			})
		}
	}

	fmt.Printf("\n")
}

// NewTrieTree create a new trie tree
func NewTrieTree() Trie {
	return Trie{}
}

func ipv4toInt(ip net.IP) string {
	fmt.Println([]byte(ip))
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
