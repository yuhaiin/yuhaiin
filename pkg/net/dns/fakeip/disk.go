package fakeip

import (
	"net/netip"
	"slices"
	"sync"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
)

type DiskFakeIPPool struct {
	current netip.Addr

	prefix netip.Prefix

	mu sync.Mutex

	cache cache.Cache
}

func NewDiskFakeIPPool(prefix netip.Prefix, db cache.Cache) *DiskFakeIPPool {
	return &DiskFakeIPPool{
		prefix:  prefix,
		current: prefix.Addr().Prev(),
		cache:   db.NewCache(prefix.String()),
	}
}

func (n *DiskFakeIPPool) getIP(s string) (netip.Addr, bool) {
	key := unsafe.Slice(unsafe.StringData(s), len(s))
	z, err := n.cache.Get(key)
	if err == nil && z != nil {
		if addr, ok := netip.AddrFromSlice(z); ok {
			return addr, true
		}

		err = n.cache.Delete(slices.Values([][]byte{key}))
		if err != nil {
			log.Warn("delete fake ip failed", "err", err)
		}
	}

	return netip.Addr{}, false
}

func (n *DiskFakeIPPool) store(s string, addr netip.Addr) {
	od, _ := n.cache.Get(addr.AsSlice())
	if od != nil {
		err := n.cache.Delete(slices.Values([][]byte{od}))
		if err != nil {
			log.Warn("delete old fake ip failed", "err", err)
		}
	}

	err := n.cache.Put(func(yield func([]byte, []byte) bool) {
		k, v := []byte(s), addr.AsSlice()
		if yield(k, v) {
			yield(v, k)
		}
	})
	if err != nil {
		log.Warn("put fake ip to cache failed", "err", err)
	}
}

func (n *DiskFakeIPPool) GetFakeIPForDomain(s string) netip.Addr {
	if z, ok := n.getIP(s); ok {
		return z
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if z, ok := n.getIP(s); ok {
		return z
	}

	looped := false

	for {
		addr := n.current.Next()

		if !n.prefix.Contains(addr) {
			n.current = n.prefix.Addr().Prev()

			if looped {
				addr := n.current.Next()
				n.current = addr
				n.store(s, addr)

				return addr
			}

			looped = true
			continue
		}

		n.current = addr

		if v, _ := n.cache.Get(addr.AsSlice()); v == nil {
			n.store(s, addr)
			return addr
		}
	}
}

func (n *DiskFakeIPPool) GetDomainFromIP(ip netip.Addr) (string, bool) {
	if !n.prefix.Contains(ip) {
		return "", false
	}

	domain, err := n.cache.Get(ip.AsSlice())
	if err != nil || domain == nil {
		return "", false
	}

	return string(domain), true
}
