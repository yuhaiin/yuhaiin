package match

import (
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

func ipv4toInt(ip net.IP) string {
	return fmt.Sprintf("%032b", binary.BigEndian.Uint32(ip)) // there ip is ip.To4()
}

func ipv6toInt(ip net.IP) string {
	// from http://golang.org/pkg/net/#pkg-constants
	// IPv6len = 16
	return fmt.Sprintf("%0128b", big.NewInt(0).SetBytes(ip)) // there ip is ip.To16()
}

// InsetOneCIDR Insert one CIDR to cidr matcher
func (c *Cidr) Insert(cidr string, mark interface{}) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	maskSize, _ := ipNet.Mask.Size()
	x := ipNet.IP.To4()
	if x != nil {
		c.v4CidrTrie.Insert(ipv4toInt(x)[:maskSize], mark)
	} else {
		c.v6CidrTrie.Insert(ipv6toInt(ipNet.IP.To16())[:maskSize], mark)
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
	c.singleTrie.Insert(ipv6toInt(ipNet.IP)[:maskSize], mark)
	return nil
}

func (c *Cidr) singleSearch(ip string) (ok bool, mark interface{}) {
	return c.singleTrie.Search(ipv6toInt(net.ParseIP(ip)))
}

// MatchWithTrie match ip with trie
func (c *Cidr) Search(ip string) (isMatch bool, mark interface{}) {
	iP := net.ParseIP(ip)
	if iP == nil {
		return false, nil
	}
	x := iP.To4()
	if iP.To4() != nil {
		return c.v4CidrTrie.Search(ipv4toInt(x))
	} else {
		return c.v6CidrTrie.Search(ipv6toInt(iP.To16()))
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
func (t *Trie) Insert(str string, mark interface{}) {
	nodeTemp := t.root
	for i := range str {
		// 1 byte is 49
		if str[i] == 49 {
			if nodeTemp.right == nil {
				nodeTemp.right = new(cidrNode)
			}
			nodeTemp = nodeTemp.right
		}
		// 0 byte is 48
		if str[i] == 48 {
			if nodeTemp.left == nil {
				nodeTemp.left = new(cidrNode)
			}
			nodeTemp = nodeTemp.left
		}
		if nodeTemp.isLast || i == len(str)-1 {
			nodeTemp.isLast = true
			nodeTemp.mark = mark
			nodeTemp.left = new(cidrNode)
			nodeTemp.right = new(cidrNode)
		}
	}
}

// Search search from trie tree
func (t *Trie) Search(str string) (isMatch bool, mark interface{}) {
	nodeTemp := t.root
	for i := range str {
		if str[i] == 49 {
			nodeTemp = nodeTemp.right
		}
		if str[i] == 48 {
			nodeTemp = nodeTemp.left
		}
		if nodeTemp == nil {
			return false, nil
		}
		if nodeTemp.isLast {
			return true, nodeTemp.mark
		}
	}
	return false, nil
}

// GetRoot get root node
func (t *Trie) GetRoot() *cidrNode {
	return t.root
}

// PrintTree print this tree
func (t *Trie) PrintTree(node *cidrNode) {
	if node.left != nil {
		t.PrintTree(node.left)
		log.Println("0")
	}
	if node.right != nil {
		t.PrintTree(node.right)
		log.Println("1")
	}
}

// NewTrieTree create a new trie tree
func NewTrieTree() Trie {
	return Trie{
		root: &cidrNode{},
	}
}
