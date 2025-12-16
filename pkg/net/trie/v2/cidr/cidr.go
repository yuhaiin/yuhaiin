package cidr

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

// Cidr cidr matcher
type Cidr[T comparable] struct {
	v4CidrTrie *Trie[T]
	v6CidrTrie *Trie[T]
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
	addr := ipNet.Addr()
	if addr.Is4() {
		c.remove(c.v4CidrTrie, addr.AsSlice(), ipNet.Bits())
	} else {
		c.remove(c.v6CidrTrie, addr.AsSlice(), ipNet.Bits())
	}
}
func (c *Cidr[T]) RemoveIP(ipNet netip.Addr, maskSize int) {
	if ipNet.Is4() {
		c.remove(c.v4CidrTrie, ipNet.AsSlice(), maskSize)
	} else {
		c.remove(c.v6CidrTrie, ipNet.AsSlice(), maskSize)
	}
}

func (c *Cidr[T]) remove(trie *Trie[T], ip []byte, maskSize int) {
	r := trie
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
	if r != nil {
		r.marks = make(map[T]struct{})
	}
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
func (c *Cidr[T]) Search(ip string) *set.ImmutableSet[T] {
	iP := net.ParseIP(ip)
	if iP == nil {
		return set.EmptyImmutableSet[T]()
	}
	return c.SearchIP(iP)
}

func (c *Cidr[T]) SearchIP(ip net.IP) *set.ImmutableSet[T] {
	if x := ip.To4(); x != nil {
		return c.v4CidrTrie.Search(x)
	} else {
		return c.v6CidrTrie.Search(ip.To16())
	}
}

func NewCidr[T comparable]() *Cidr[T] {
	cidrMapper := new(Cidr[T])
	cidrMapper.v4CidrTrie = NewTrie[T]()
	cidrMapper.v6CidrTrie = NewTrie[T]()
	return cidrMapper
}
