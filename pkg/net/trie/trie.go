package trie

import (
	"context"
	"errors"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/cidr"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

type Trie[T any] struct {
	cidr   *cidr.Cidr[T]
	domain *domain.Fqdn[T]
}

func (x *Trie[T]) Insert(str string, mark T) {
	if str == "" {
		return
	}

	ipNet, err := netip.ParsePrefix(str)
	if err == nil {
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

var ErrSkipResolver = errors.New("skip resolve domain")

var SkipResolver = netapi.ErrorResolver(func(domain string) error { return ErrSkipResolver })

func (x *Trie[T]) Search(ctx context.Context, addr netapi.Address) (mark T, ok bool) {
	if addr.Type() == netapi.IP {
		return x.cidr.SearchIP(yerror.Must(addr.IP(ctx)))
	}

	if mark, ok = x.domain.Search(addr); ok {
		return
	}

	if ips, err := addr.IP(ctx); err == nil {
		mark, ok = x.cidr.SearchIP(ips)
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

func (x *Trie[T]) SearchWithDefault(ctx context.Context, addr netapi.Address, defaultT T) T {
	t, ok := x.Search(ctx, addr)
	if ok {
		return t
	}

	return defaultT
}

func (x *Trie[T]) Clear() error {
	x.cidr = cidr.NewCidrMapper[T]()
	x.domain = domain.NewDomainMapper[T]()
	return nil
}

func NewTrie[T any]() *Trie[T] {
	return &Trie[T]{cidr: cidr.NewCidrMapper[T](), domain: domain.NewDomainMapper[T]()}
}
