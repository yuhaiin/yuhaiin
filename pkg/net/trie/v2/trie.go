package trie

import (
	"context"
	"errors"
	"iter"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/cache/pebble"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/cidr"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/domain"
)

type Trie[T comparable] struct {
	cidr   *cidr.Cidr[T]
	domain domain.Trie[T]
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

func (x *Trie[T]) Batch(iter iter.Seq2[string, T]) error {
	return x.domain.Batch(func(yield func(string, T) bool) {
		for str, mark := range iter {
			if str == "" {
				continue
			}

			if ipNet, err := netip.ParsePrefix(str); err == nil {
				x.cidr.InsertCIDR(ipNet, mark)
				continue
			}

			if ip, err := netip.ParseAddr(str); err == nil {
				mask := 128
				if ip.Is4() {
					mask = 32
				}
				x.cidr.InsertIP(ip, mask, mark)
				continue
			}

			if !yield(str, mark) {
				return
			}
		}
	})
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
	return err
}

type Options[T comparable] struct {
	Codec codec.Codec[T]
	// Badger *badger.Cache
	Pebble *pebble.Cache
}

func WithCodec[T comparable](codec codec.Codec[T]) func(*Options[T]) {
	return func(o *Options[T]) {
		o.Codec = codec
	}
}

// func WithBadger(cache *badger.Cache) func(*Options[string]) {
// 	return func(o *Options[string]) {
// 		o.Badger = cache
// 	}
// }

func WithPebble(cache *pebble.Cache) func(*Options[string]) {
	return func(o *Options[string]) {
		o.Pebble = cache
	}
}

// NewTrie create a new trie
// if cache is nil, use memory trie
func NewTrie[T comparable](opts ...func(*Options[T])) *Trie[T] {
	opt := Options[T]{Codec: codec.GobCodec[T]{}}
	for _, o := range opts {
		o(&opt)
	}
	var dt domain.Trie[T]

	if opt.Pebble != nil {
		dt = domain.NewDiskFqdn(domain.NewDiskPebbleTrie(opt.Pebble, opt.Codec))
	} else {
		dt = domain.NewTrie[T]()
	}

	return &Trie[T]{
		cidr:   cidr.NewCidr[T](),
		domain: dt,
	}
}
