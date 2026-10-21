package fakeip

import (
	"database/sql"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const fakeIPCacheCapacity = 4096

// Both indexes refer to the same bounded slot array. Replacing a cache slot
// never evicts a persistent mapping or changes its active lease count.
type fakeIPCache struct {
	domains  map[string]int
	ips      map[netip.Addr]int
	entries  []fakeIPCacheEntry
	next     int
	capacity int
}

type fakeIPCacheEntry struct {
	domain    string
	ip        netip.Addr
	lastTouch atomic.Int64
}

func newFakeIPCache(capacity int) fakeIPCache {
	return fakeIPCache{
		capacity: capacity,
	}
}

// Pool readers hold the shared RLock; only the sampled touch timestamp changes
// on a hit. Queue the corresponding durable touch before dropping that lock.
func (e *fakeIPCacheEntry) touch(now time.Time) bool {
	previous := e.lastTouch.Load()
	return now.UnixNano()-previous >= sqliteFakeIPTouchInterval.Nanoseconds() && e.lastTouch.CompareAndSwap(previous, now.UnixNano())
}

func (c *fakeIPCache) remove(index int) {
	e := &c.entries[index]
	delete(c.domains, e.domain)
	delete(c.ips, e.ip)
	e.domain, e.ip = "", netip.Addr{}
}

func (c *fakeIPCache) removeDomain(domain string) {
	if index, ok := c.domains[domain]; ok {
		c.remove(index)
	}
}

func (c *fakeIPCache) put(domain string, ip netip.Addr, lastUsedAt int64) {
	// Bound retained string storage as well as the number of cache entries.
	// The persistent pool can still handle callers supplying longer strings.
	c.removeDomain(domain)
	if index, ok := c.ips[ip]; ok {
		c.remove(index)
	}
	if len(domain) > 253 {
		return
	}
	if c.entries == nil {
		c.entries = make([]fakeIPCacheEntry, c.capacity)
		c.domains = make(map[string]int, c.capacity)
		c.ips = make(map[netip.Addr]int, c.capacity)
	}
	index := c.next
	if c.entries[index].ip.IsValid() {
		c.remove(index)
	}
	e := &c.entries[index]
	e.domain, e.ip = strings.Clone(domain), ip
	e.lastTouch.Store(lastUsedAt)
	c.domains[e.domain], c.ips[ip] = index, index
	c.next = (index + 1) % len(c.entries)
}

type fakeIPPoolKey struct {
	db     *sql.DB
	prefix netip.Prefix
}

// Multiple handles to the same database/prefix share invalidation and lease
// ownership. Their touch queues are flushed together before any address reuse.
type fakeIPPoolState struct {
	mu     sync.RWMutex
	active map[netip.Addr]uint32
	cache  fakeIPCache
	owners map[*SQLiteFakeIPPool]struct{}
	refs   int
}

var fakeIPPoolStates = struct {
	sync.Mutex
	items map[fakeIPPoolKey]*fakeIPPoolState
}{items: make(map[fakeIPPoolKey]*fakeIPPoolState)}

func (p *SQLiteFakeIPPool) attachState() {
	key := fakeIPPoolKey{p.db, p.prefix}
	fakeIPPoolStates.Lock()
	s := fakeIPPoolStates.items[key]
	if s == nil {
		s = &fakeIPPoolState{
			active: make(map[netip.Addr]uint32),
			cache:  newFakeIPCache(int(min(uint64(fakeIPCacheCapacity), p.maxNum))),
			owners: make(map[*SQLiteFakeIPPool]struct{}),
		}
		fakeIPPoolStates.items[key] = s
	}
	s.refs++
	fakeIPPoolStates.Unlock()
	p.state, p.mu, p.active, p.cache = s, &s.mu, s.active, &s.cache
	p.mu.Lock()
	s.owners[p] = struct{}{}
	p.mu.Unlock()
}

func (p *SQLiteFakeIPPool) detachState() {
	p.mu.Lock()
	delete(p.state.owners, p)
	p.mu.Unlock()
	fakeIPPoolStates.Lock()
	defer fakeIPPoolStates.Unlock()
	p.state.refs--
	if p.state.refs == 0 {
		p.mu.Lock()
		p.state.cache = newFakeIPCache(p.cache.capacity)
		p.mu.Unlock()
		delete(fakeIPPoolStates.items, fakeIPPoolKey{p.db, p.prefix})
	}
}
