package trie

import (
	"context"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/cidr"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
)

type Trie[T any] struct {
	cidr   *cidr.Cidr[T]
	domain *domain.Fqdn[T]
}

func (x *Trie[T]) Insert(str string, mark T) {
	if str == "" {
		return
	}

	if ipNet, err := netip.ParsePrefix(str); err == nil {
		x.cidr.InsertCIDR(ipNet, mark)
		return
	}

	if ip, err := netip.ParseAddr(str); err == nil {
		mask := 128
		if ip.Is4() {
			mask = 32
		}
		x.cidr.InsertIP(ip, mask, mark)
		return
	}

	x.domain.Insert(str, mark)
}

func (x *Trie[T]) SearchFqdn(addr netapi.Address) (mark T, ok bool) {
	if !addr.IsFqdn() {
		return x.cidr.SearchIP(addr.(netapi.IPAddress).AddrPort().Addr().AsSlice())
	}

	return x.domain.Search(addr)
}

func (x *Trie[T]) Search(ctx context.Context, addr netapi.Address) (mark T, ok bool) {
	if mark, ok = x.SearchFqdn(addr); ok {
		return
	}

	store := netapi.GetContext(ctx)

	matchResolver := store.ConnOptions().Resolver().Resolver()
	if matchResolver == nil {
		return
	}

	ips, err := matchResolver.LookupIP(ctx, addr.Hostname())
	if err != nil {
		return
	}

	for ip := range ips.Iter() {
		if mark, ok = x.cidr.SearchIP(ip); ok {
			return
		}
	}

	return
}

func (x *Trie[T]) Remove(str string) {
	if str == "" {
		return
	}

	ipNet, err := netip.ParsePrefix(str)
	if err == nil {
		x.cidr.RemoveCIDR(ipNet)
		return
	}

	if ip, err := netip.ParseAddr(str); err == nil {
		mask := 128
		if ip.Is4() {
			mask = 32
		}
		x.cidr.RemoveIP(ip, mask)
		return
	}

	x.domain.Remove(str)
}

func (x *Trie[T]) Clear() error {
	x.cidr = cidr.NewCidrTrie[T]()
	x.domain = domain.NewDomainMapper[T]()
	return nil
}

func NewTrie[T any]() *Trie[T] {
	return &Trie[T]{cidr: cidr.NewCidrTrie[T](), domain: domain.NewDomainMapper[T]()}
}
