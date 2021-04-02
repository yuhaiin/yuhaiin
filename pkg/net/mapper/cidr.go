package mapper

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net"
)

// Cidr cidr matcher
type Cidr struct {
	v4CidrTrie Trie
	v6CidrTrie Trie
	singleTrie Trie
}

var bc = []byte{128, 64, 32, 16, 8, 4, 2, 1}

// InsetOneCIDR Insert one CIDR to cidr matcher
func (c *Cidr) Insert(cidr string, mark interface{}) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	maskSize, _ := ipNet.Mask.Size()
	x := ipNet.IP.To4()
	if x != nil {
		c.v4CidrTrie.Insert(x, maskSize, mark)
	} else {
		c.v6CidrTrie.Insert(ipNet.IP.To16(), maskSize, mark)
	}
	return nil
}

func (c *Cidr) singleInsert(cidr string, mark interface{}) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
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
	if x := iP.To4(); x != nil {
		return c.v4CidrTrie.Search(x)
	} else {
		return c.v6CidrTrie.Search(iP.To16())
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
// Trie trie tree
type Trie struct {
	root *cidrNode
}

type cidrNode struct {
	isLast bool
	mark   interface{}
	left   *cidrNode
	right  *cidrNode
}

// Insert insert node to tree
func (t *Trie) Insert(ip net.IP, maskSize int, mark interface{}) {
	nodeTemp := t.root
	for i := range ip {
		for i2 := range bc {
			// fmt.Println(i*8 + i2 + 1)
			if ip[i]&bc[i2] != 0 {
				if nodeTemp.right == nil {
					nodeTemp.right = new(cidrNode)
				}
				nodeTemp = nodeTemp.right
			} else {
				if nodeTemp.left == nil {
					nodeTemp.left = new(cidrNode)
				}
				nodeTemp = nodeTemp.left
			}

			if nodeTemp.isLast || i*8+i2+1 == maskSize {
				nodeTemp.isLast = true
				nodeTemp.mark = mark
				nodeTemp.left = new(cidrNode)
				nodeTemp.right = new(cidrNode)
				return
			}
		}
	}
}

// Search search from trie tree
func (t *Trie) Search(ip net.IP) (mark interface{}, ok bool) {
	nodeTemp := t.root
	for i := range ip {
		for i2 := range bc {
			if ip[i]&bc[i2] != 0 { // bit = 1
				nodeTemp = nodeTemp.right
			} else { // bit = 0
				nodeTemp = nodeTemp.left
			}
			if nodeTemp == nil {
				return nil, false
			}
			if nodeTemp.isLast {
				return nodeTemp.mark, true
			}
		}
	}
	return nil, false
}

// GetRoot get root node
func (t *Trie) GetRoot() *cidrNode {
	return t.root
}

// PrintTree print this tree
func (t *Trie) PrintTree(node *cidrNode) {
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
		c *cidrNode
		s string
	}
	x := list.List{}
	x.PushBack(&p{
		c: t.root,
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
	return Trie{
		root: &cidrNode{},
	}
}

func ipv4toInt(ip net.IP) string {
	fmt.Println([]byte(ip))
	return fmt.Sprintf("%032b", binary.BigEndian.Uint32(ip)) // there ip is ip.To4()
}

func ipv4toInt2(ip net.IP) []byte {
	s := make([]byte, 0, 32)
	for i := range ip {
		for i2 := range bc {
			if ip[i]&bc[i2] != 0 {
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
		for i2 := range bc {
			if ip[i]&bc[i2] != 0 {
				s = append(s, 1)
			} else {
				s = append(s, 0)
			}
		}
	}
	return s
}
