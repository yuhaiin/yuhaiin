package trie

import (
	"context"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/cidr"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/domain"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

type Trie[T comparable] struct {
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

func (x *Trie[T]) SearchFqdn(addr netapi.Address) *set.Set[T] {
	if !addr.IsFqdn() {
		return x.cidr.SearchIP(addr.(netapi.IPAddress).AddrPort().Addr().AsSlice())
	}

	return x.domain.Search(addr)
}

func (x *Trie[T]) Search(ctx context.Context, addr netapi.Address) *set.Set[T] {
	if mark := x.SearchFqdn(addr); mark.Len() > 0 || !addr.IsFqdn() {
		return mark
	}

	ips, err := netapi.GetContext(ctx).ConnOptions().RouteIPs(ctx, addr)
	if err != nil {
		return set.NewSet[T]()
	}

	for ip := range ips.Iter() {
		if mark := x.cidr.SearchIP(ip); mark.Len() > 0 {
			return mark
		}
	}

	return set.NewSet[T]()
}

func (x *Trie[T]) Remove(str string, mark T) {
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

	x.domain.Remove(str, mark)
}

func (x *Trie[T]) Clear() error {
	x.cidr = cidr.NewCidr[T]()
	x.domain = domain.NewTrie[T]()
	return nil
}

func NewTrie[T comparable]() *Trie[T] {
	return &Trie[T]{cidr: cidr.NewCidr[T](), domain: domain.NewTrie[T]()}
}
