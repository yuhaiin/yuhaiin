package trie

import (
	"context"
	"errors"
	"iter"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/cache/pebble"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/cidr"
	diskcidr "github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/cidr/disk"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/disk"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/domain"
)

type Trie[T comparable] struct {
	cidr   cidrMatcher[T]
	domain domain.Trie[T]
}

type cidrMatcher[T comparable] interface {
	InsertCIDR(netip.Prefix, T)
	InsertIP(netip.Addr, int, T)
	SearchIP(net.IP) []T
	RemoveCIDR(netip.Prefix)
	RemoveIP(netip.Addr, int)
	Clear() error
	Close() error
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
	return errors.Join(x.cidr.Clear(), x.domain.Clear())
}

func (x *Trie[T]) Close() error {
	var err error
	if er := x.cidr.Close(); er != nil {
		err = errors.Join(err, er)
	}
	if er := x.domain.Close(); er != nil {
		err = errors.Join(err, er)
	}
	return err
}

type Options[T comparable] struct {
	Codec    codec.Codec[T]
	Pebble   *pebble.Cache
	Mmap     string
	MmapCIDR string
}

func WithCodec[T comparable](codec codec.Codec[T]) func(*Options[T]) {
	return func(o *Options[T]) {
		o.Codec = codec
	}
}

func WithPebble(cache *pebble.Cache) func(*Options[string]) {
	return func(o *Options[string]) {
		o.Pebble = cache
	}
}

func WithMmap(path string) func(*Options[string]) {
	return func(o *Options[string]) {
		o.Mmap = path
	}
}

// WithMmapCIDR enables the optional disk-backed CIDR matcher. The default
// remains the in-memory matcher. Use a separate directory from WithMmap when
// both disk backends are enabled.
func WithMmapCIDR(path string) func(*Options[string]) {
	return func(o *Options[string]) {
		o.MmapCIDR = path
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
	cm, err := newCIDRMatcher(opt)
	if err != nil {
		panic(err)
	}

	if opt.Mmap != "" {
		dt, err := disk.NewTrie(opt.Mmap, opt.Codec)
		if err != nil {
			_ = cm.Close()
			panic(err)
		}
		return &Trie[T]{
			cidr:   cm,
			domain: newDiskDomain(dt),
		}
	}

	if opt.Pebble != nil {
		dt = domain.NewDiskFqdn(domain.NewDiskPebbleTrie(opt.Pebble, opt.Codec))
	} else {
		dt = domain.NewTrie[T]()
	}

	return &Trie[T]{
		cidr:   cm,
		domain: dt,
	}
}

func newCIDRMatcher[T comparable](options Options[T]) (cidrMatcher[T], error) {
	if options.MmapCIDR != "" {
		return diskcidr.NewTrie(options.MmapCIDR, options.Codec)
	}
	return cidr.NewCidr[T](), nil
}
