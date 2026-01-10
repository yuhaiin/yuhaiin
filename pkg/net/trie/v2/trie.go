package trie

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/cidr"
	domain "github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/domain/disk"
)

type Trie[T comparable] struct {
	cidr   *cidr.Cidr[T]
	domain *domain.Fqdn[T]
	path   string
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

func (x *Trie[T]) SearchFqdn(addr netapi.Address) []T {
	if !addr.IsFqdn() {
		return x.cidr.SearchIP(addr.(netapi.IPAddress).AddrPort().Addr().AsSlice())
	}

	return x.domain.Search(addr)
}

func (x *Trie[T]) Search(ctx context.Context, addr netapi.Address) []T {
	if mark := x.SearchFqdn(addr); len(mark) > 0 || !addr.IsFqdn() {
		return mark
	}

	ips, err := netapi.GetContext(ctx).ConnOptions().RouteIPs(ctx, addr)
	if err != nil {
		return nil
	}

	for ip := range ips.Iter() {
		if mark := x.cidr.SearchIP(ip); len(mark) > 0 {
			return mark
		}
	}

	return nil
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
	return x.domain.Clear()
}

func (x *Trie[T]) Close() error {
	var err error
	if er := x.domain.Close(); er != nil {
		err = errors.Join(err, er)
	}
	if er := os.RemoveAll(x.path); er != nil {
		err = errors.Join(err, er)
	}
	return err
}

func NewTrie[T comparable]() *Trie[T] {
	path := filepath.Join(configuration.DataDir.Load(),
		fmt.Sprintf("trie.%s.db", rand.Text()),
	)
	return &Trie[T]{
		cidr:   cidr.NewCidr[T](),
		domain: domain.NewTrie[T](path),
		path:   path,
	}
}
