package fakeip

import (
	"math"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
)

type FakeIPPool struct {
	current    netip.Addr
	domainToIP *fakeLru

	prefix netip.Prefix

	mu sync.Mutex
}

func NewFakeIPPool(prefix netip.Prefix, db cache.Cache) *FakeIPPool {
	prefix = prefix.Masked()

	lenSize := 32
	if prefix.Addr().Is6() {
		lenSize = 128
	}

	var lruSize int
	if prefix.Bits() == lenSize {
		lruSize = 0
	} else {
		size := math.Pow(2, float64(lenSize-prefix.Bits())) - 1
		if size > 65535 {
			lruSize = 65535
		} else {
			lruSize = int(size)
		}
	}

	return &FakeIPPool{
		prefix:     prefix,
		current:    prefix.Addr().Prev(),
		domainToIP: newFakeLru(lruSize, db, prefix),
	}
}

func (n *FakeIPPool) GetFakeIPForDomain(s string) netip.Addr {
	if z, ok := n.domainToIP.Load(s); ok {
		metrics.Counter.AddFakeIPCacheHit()
		return z
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if z, ok := n.domainToIP.Load(s); ok {
		metrics.Counter.AddFakeIPCacheHit()
		return z
	}

	metrics.Counter.AddFakeIPCacheMiss()

	if v, ok := n.domainToIP.LastPopValue(); ok {
		n.domainToIP.Add(s, v)
		return v
	}

	looped := false

	for {
		addr := n.current.Next()

		if !n.prefix.Contains(addr) {
			n.current = n.prefix.Addr().Prev()

			if looped {
				addr := n.current.Next()
				n.current = addr
				n.domainToIP.Add(s, addr)
				return addr
			}

			looped = true
			continue
		}

		n.current = addr

		if !n.domainToIP.ValueExist(addr) {
			n.domainToIP.Add(s, addr)
			return addr
		}
	}
}

func (n *FakeIPPool) GetDomainFromIP(ip netip.Addr) (string, bool) {
	if !n.prefix.Contains(ip) {
		return "", false
	}

	return n.domainToIP.ReverseLoad(ip)
}

func (n *FakeIPPool) Prefix() netip.Prefix {
	return n.prefix
}
