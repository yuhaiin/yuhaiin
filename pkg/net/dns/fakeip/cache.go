package fakeip

import (
	"errors"
	"net/netip"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

type fakeLru struct {
	bbolt cache.Cache

	LRU     *lru.ReverseSyncLru[string, netip.Addr]
	iprange netip.Prefix

	Size int
}

func newFakeLru(size int, db cache.Cache, iprange netip.Prefix) *fakeLru {
	var bboltCache cache.Cache
	if iprange.Addr().Unmap().Is6() {
		bboltCache = db.NewCache("fakedns_cachev6")
	} else {
		bboltCache = db.NewCache("fakedns_cache")
	}

	z := &fakeLru{Size: size, bbolt: bboltCache, iprange: iprange}

	if size <= 0 {
		return z
	}

	z.LRU = lru.NewSyncReverseLru(
		lru.WithLruOptions(
			lru.WithCapacity[string, netip.Addr](int(size)),
			lru.WithOnRemove(func(s string, v netip.Addr) {
				_ = bboltCache.Delete(slices.Values([][]byte{[]byte(s), v.AsSlice()}))
			}),
		),
		lru.WithOnValueChanged[string](func(old, new netip.Addr) {
			_ = bboltCache.Delete(slices.Values([][]byte{old.AsSlice()}))
		}),
	)

	err := bboltCache.Range(func(k, v []byte) bool {
		ip, ok := netip.AddrFromSlice(k)
		if !ok {
			return true
		}

		if iprange.Contains(ip) {
			z.LRU.Add(string(v), ip)
		}

		return true
	})
	if err != nil && !errors.Is(err, cache.ErrBucketNotExist) {
		log.Error("fakeip range cache failed", "err", err)
	}

	log.Info("fakeip lru init", "get cache", z.LRU.Len(), "isIpv6", iprange.Addr().Unmap().Is6(), "capacity", size)

	return z
}

func (f *fakeLru) Load(host string) (netip.Addr, bool) {
	if f.Size <= 0 {
		return netip.Addr{}, false
	}

	z, ok := f.LRU.Load(host)
	if ok {
		return z, ok
	}

	return netip.Addr{}, false
}

func (f *fakeLru) Add(host string, ip netip.Addr) {
	if f.Size <= 0 {
		return
	}
	f.LRU.Add(host, ip)

	if f.bbolt != nil {
		host, ip := []byte(host), ip.AsSlice()
		_ = f.bbolt.Put(func(yield func([]byte, []byte) bool) {
			if !yield(host, ip) {
				return
			}
			_ = yield(ip, host)
		})
	}
}

func (f *fakeLru) ValueExist(ip netip.Addr) bool {
	if f.Size <= 0 {
		return false
	}

	if f.LRU.ValueExist(ip) {
		return true
	}

	return false
}

func (f *fakeLru) ReverseLoad(ip netip.Addr) (string, bool) {
	if f.Size <= 0 {
		return "", false
	}

	host, ok := f.LRU.ReverseLoad(ip)
	if ok {
		return host, ok
	}

	v, _ := f.bbolt.Get(ip.AsSlice())
	if host = string(v); host != "" {
		return host, true
	}

	return "", false
}

func (f *fakeLru) LastPopValue() (netip.Addr, bool) {
	if f.Size <= 0 {
		return netip.Addr{}, false
	}
	return f.LRU.LastPopValue()
}
