package cidr

import (
	"fmt"
	"net"
	"net/netip"
)

// Cidr cidr matcher
type Cidr[T any] struct {
	v4CidrTrie Trie[T]
	v6CidrTrie Trie[T]
}

// InsetOneCIDR Insert one CIDR to cidr matcher
func (c *Cidr[T]) Insert(cidr string, mark T) error {
	ipNet, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("parse cidr [%s] failed: %w", cidr, err)
	}
	c.InsertCIDR(ipNet, mark)
	return nil
}

func (c *Cidr[T]) RemoveCIDR(ipNet netip.Prefix) {
	//TODO
}
func (c *Cidr[T]) RemoveIP(ipNet netip.Addr, maskSIze int) {
	//TODO
}

func (c *Cidr[T]) InsertCIDR(ipNet netip.Prefix, mark T) {
	if ipNet.Addr().Is4() {
		c.v4CidrTrie.Insert(ipNet.Addr().AsSlice(), ipNet.Bits(), mark)
	} else {
		c.v6CidrTrie.Insert(ipNet.Addr().AsSlice(), ipNet.Bits(), mark)
	}
}

func (c *Cidr[T]) InsertIP(ip netip.Addr, maskSize int, mark T) {
	if ip.Is4() {
		c.v4CidrTrie.Insert(ip.AsSlice(), maskSize, mark)
	} else {
		c.v6CidrTrie.Insert(ip.AsSlice(), maskSize, mark)
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
