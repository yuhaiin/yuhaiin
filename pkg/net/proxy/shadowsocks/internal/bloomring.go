package internal

import (
	"hash/fnv"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks/bloom"
)

// simply use Double FNV here as our Bloom Filter hash
func doubleFNV(b []byte) (uint64, uint64) {
	hx := fnv.New64()
	hx.Write(b)
	x := hx.Sum64()
	hy := fnv.New64a()
	hy.Write(b)
	y := hy.Sum64()
	return x, y
}

type BloomRing struct {
	slots        []bloom.Filter
	slotCapacity int
	slotPosition int
	slotCount    int
	entryCounter int
	mu           sync.RWMutex
}

func NewBloomRing(slot, capacity int, falsePositiveRate float64) *BloomRing {
	// Calculate entries for each slot
	r := &BloomRing{
		slotCapacity: capacity / slot,
		slotCount:    slot,
		slots:        make([]bloom.Filter, slot),
	}
	for i := range slot {
		r.slots[i] = bloom.New(r.slotCapacity, falsePositiveRate, doubleFNV)
	}
	return r
}

func (r *BloomRing) Add(b []byte) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.add(b)
}

func (r *BloomRing) add(b []byte) {
	slot := r.slots[r.slotPosition]
	if r.entryCounter > r.slotCapacity {
		// Move to next slot and reset
		r.slotPosition = (r.slotPosition + 1) % r.slotCount
		slot = r.slots[r.slotPosition]
		slot.Reset()
		r.entryCounter = 0
	}
	r.entryCounter++
	slot.Add(b)
}

func (r *BloomRing) Test(b []byte) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	test := r.test(b)
	return test
}

func (r *BloomRing) test(b []byte) bool {
	for _, s := range r.slots {
		if s.Test(b) {
			return true
		}
	}
	return false
}

func (r *BloomRing) Check(b []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Test(b) {
		return true
	}
	r.Add(b)
	return false
}
