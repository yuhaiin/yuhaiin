package lightweight

import (
	"math/bits"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const bufferCharge = 80

var bufferSizes = [...]int{64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}

// An ownedBuffer is exclusively owned by either one connection, the output
// queue/writer, or its cache. A connection may split it into multiple read-only
// views, under its own lock. Publishing through the output queue or locked cache
// transfers exclusive ownership; packet I/O must not retain the borrowed slice.
// refs is therefore never accessed concurrently, even across queue transfers.
type ownedBuffer struct {
	cacheNext           *ownedBuffer
	data                []byte
	pool                *bufferPool
	class               int
	cost, refs          int
	offset, segmentSize int
}

func (b *ownedBuffer) hold() { b.refs++ }
func (b *ownedBuffer) release() {
	if b == nil {
		return
	}
	b.refs--
	if b.refs == 0 {
		b.pool.put(b)
	}
}

type bufferPool struct {
	stack      *Stack
	mu         sync.RWMutex
	closed     bool
	classes    [len(bufferSizes)]bufferFreeList
	segments   segmentFreeList
	cached     atomic.Int64
	cacheLimit int64
	activity   atomic.Bool
	expiring   atomic.Bool
	idleJob    timerJob
}

func (p *bufferPool) init(s *Stack) {
	p.stack = s
	p.idleJob = timerJob{index: -1, run: p.expire}
	// A 100-flow 64 KiB burst needs about 9 MiB for immutable application
	// chunks, their descriptors and output frames together. Keeping that set
	// avoids allocation/GC peaks; small configurations still cap it at 1/8.
	p.cacheLimit = min(10<<20, s.config.MemoryLimit/8)
}
func bufferClass(n int) (int, int) {
	if n <= 64 {
		return 0, 64
	}
	i := bits.Len(uint(n-1)) - 6
	if i >= len(bufferSizes) {
		return -1, n
	}
	return i, bufferSizes[i]
}
func (p *bufferPool) canGet(n int) bool {
	if n < 0 || n > maxPacketBufferSize {
		return false
	}
	i, size := bufferClass(n)
	if i >= 0 && p.classes[i].available() {
		return true
	}
	// A cached allocation in another size class can be evicted on pressure.
	return p.stack.memory.Load()-p.cached.Load()+int64(size+bufferCharge) <= p.stack.config.MemoryLimit
}
func (p *bufferPool) get(n int) (*ownedBuffer, error) {
	if n < 0 || n > maxPacketBufferSize {
		return nil, ErrLimit
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed || p.stack.closed() {
		return nil, net.ErrClosed
	}
	i, size := bufferClass(n)
	if i >= 0 {
		if b := p.classes[i].pop(); b != nil {
			p.activity.Store(true)
			p.cached.Add(-int64(b.cost))
			b.data = b.data[:n]
			b.refs = 1
			b.offset, b.segmentSize = 0, 0
			return b, nil
		}
	}
	cost := size + bufferCharge
	if !p.stack.reserve(cost) {
		return nil, ErrLimit
	}
	return &ownedBuffer{data: make([]byte, size)[:n], pool: p, class: i, cost: cost, refs: 1}, nil
}

// Cache admission has its own small byte budget in addition to the global
// retained-memory budget. All size classes compete for it; a burst of jumbo
// packets cannot multiply the cache limit by the number of classes.
func (p *bufferPool) cacheReserve(n int) bool {
	for {
		old := p.cached.Load()
		if int64(n) > p.cacheLimit-old {
			return false
		}
		if p.cached.CompareAndSwap(old, old+int64(n)) {
			return true
		}
	}
}
func (p *bufferPool) put(b *ownedBuffer) {
	p.mu.RLock()
	if !p.closed && !p.stack.closed() && b.class >= 0 && p.cacheReserve(b.cost) {
		b.data = b.data[:0]
		if p.classes[b.class].push(b) {
			p.activity.Store(true)
			if p.expiring.CompareAndSwap(false, true) {
				p.stack.scheduler.set(&p.idleJob, time.Now().Add(2*time.Second))
			}
			p.mu.RUnlock()
			p.stack.wakeOutput()
			return
		}
		p.cached.Add(-int64(b.cost))
	}
	p.mu.RUnlock()
	p.stack.release(b.cost)
}

// trim is only used when the global allocation budget is exhausted. Cache
// entries remain part of that budget, so recycling can never hide retained RAM.
func (p *bufferPool) trim(need int) bool {
	freed := false
	for i := len(p.classes) - 1; i >= 0; i-- {
		for p.stack.memory.Load()+int64(need) > p.stack.config.MemoryLimit {
			b := p.classes[i].pop()
			if b == nil {
				break
			}
			p.cached.Add(-int64(b.cost))
			p.stack.memory.Add(-int64(b.cost))
			freed = true
		}
	}
	for p.stack.memory.Load()+int64(need) > p.stack.config.MemoryLimit {
		if p.segments.pop() == nil {
			break
		}
		p.cached.Add(-segmentCharge)
		p.stack.memory.Add(-segmentCharge)
		freed = true
	}
	return freed
}

// One stack-wide job reclaims a traffic burst after 2-4 idle seconds. An
// inactive cache leaves no periodic timer behind (important for mobile idle).
func (p *bufferPool) expire(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	if p.activity.Swap(false) {
		p.stack.scheduler.set(&p.idleJob, now.Add(2*time.Second))
		return
	}
	p.drain()
	p.expiring.Store(false)
	p.stack.wakeOutput()
}
func (p *bufferPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.stack.scheduler.set(&p.idleJob, time.Time{})
	p.drain()
}
func (p *bufferPool) drain() {
	for i := range p.classes {
		for {
			b := p.classes[i].pop()
			if b == nil {
				break
			}
			p.cached.Add(-int64(b.cost))
			p.stack.memory.Add(-int64(b.cost))
		}
	}
	for p.segments.pop() != nil {
		p.cached.Add(-segmentCharge)
		p.stack.memory.Add(-segmentCharge)
	}
}

// takeSegment consumes a reservation already made by the caller. A cached
// descriptor is still charged, so its replacement reservation is redundant.
func (p *bufferPool) takeSegment() *sendSegment {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if v := p.segments.pop(); v != nil {
		p.cached.Add(-segmentCharge)
		p.stack.release(segmentCharge)
		p.activity.Store(true)
		return v
	}
	return new(sendSegment)
}

func (p *bufferPool) releaseSegment(v *sendSegment) {
	owner := v.owner
	// Clear timing, SACK and data references before either object becomes
	// visible to another connection. ACK sampling keeps its own value copy.
	*v = sendSegment{}
	if owner == nil { // SYN/FIN descriptors belong to the connection charge.
		return
	}
	owner.release()
	p.mu.RLock()
	if !p.closed && !p.stack.closed() && p.cacheReserve(segmentCharge) {
		if p.segments.push(v) {
			p.activity.Store(true)
			if p.expiring.CompareAndSwap(false, true) {
				p.stack.scheduler.set(&p.idleJob, time.Now().Add(2*time.Second))
			}
			p.mu.RUnlock()
			// The retained payload may still have other views. Making only this
			// descriptor evictable can nevertheless admit a waiting ACK/packet.
			p.stack.wakeOutput()
			return
		}
		p.cached.Add(-segmentCharge)
	}
	p.mu.RUnlock()
	p.stack.release(segmentCharge)
}
