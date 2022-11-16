package cidr

import (
	"fmt"
	"net"
)

// Cidr cidr matcher
type Cidr[T any] struct {
	v4CidrTrie Trie[T]
	v6CidrTrie Trie[T]
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

func (c *Cidr[T]) InsertIP(ip net.IP, maskSize int, mark T) {
	if x := ip.To4(); x != nil {
		c.v4CidrTrie.Insert(x, maskSize, mark)
	} else {
		c.v6CidrTrie.Insert(ip.To16(), maskSize, mark)
	}
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

func NewCidrMapper[T any]() *Cidr[T] {
	cidrMapper := new(Cidr[T])
	cidrMapper.v4CidrTrie = NewTrieTree[T]()
	cidrMapper.v6CidrTrie = NewTrieTree[T]()
	return cidrMapper
}
