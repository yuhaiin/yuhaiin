package lightweight

import (
	"math/bits"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const bufferCharge = 64

var bufferSizes = [...]int{64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384}

// An ownedBuffer is exclusively owned by either one connection, the output
// queue/writer, or its cache. A connection may split it into multiple read-only
// views, under its own lock. Publishing through the output/cache channels
// transfers exclusive ownership; packet I/O must not retain the borrowed slice.
// refs is therefore never accessed concurrently, even across queue transfers.
type ownedBuffer struct {
	data       []byte
	pool       *bufferPool
	class      int
	cost, refs int
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
	classes    [len(bufferSizes)]chan *ownedBuffer
	cached     atomic.Int64
	cacheLimit int64
	activity   atomic.Bool
	expiring   atomic.Bool
	idleJob    timerJob
}

func (p *bufferPool) init(s *Stack) {
	p.stack = s
	p.idleJob = timerJob{index: -1, run: p.expire}
	p.cacheLimit = min(8<<20, s.config.MemoryLimit/8)
	for i := range bufferSizes {
		p.classes[i] = make(chan *ownedBuffer, 512)
	}
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
	if n < 0 || n > 65575 {
		return false
	}
	i, size := bufferClass(n)
	if i >= 0 && len(p.classes[i]) > 0 {
		return true
	}
	// A cached allocation in another size class can be evicted on pressure.
	return p.stack.memory.Load()-p.cached.Load()+int64(size+bufferCharge) <= p.stack.config.MemoryLimit
}
func (p *bufferPool) get(n int) (*ownedBuffer, error) {
	if n < 0 || n > 65575 {
		return nil, ErrLimit
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed || p.stack.closed() {
		return nil, net.ErrClosed
	}
	i, size := bufferClass(n)
	if i >= 0 {
		select {
		case b := <-p.classes[i]:
			p.activity.Store(true)
			p.cached.Add(-int64(b.cost))
			b.data = b.data[:n]
			b.refs = 1
			return b, nil
		default:
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
		select {
		case p.classes[b.class] <- b:
			p.activity.Store(true)
			if p.expiring.CompareAndSwap(false, true) {
				p.stack.scheduler.set(&p.idleJob, time.Now().Add(2*time.Second))
			}
			p.mu.RUnlock()
			p.stack.wakeOutput()
			return
		default:
			p.cached.Add(-int64(b.cost))
		}
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
			select {
			case b := <-p.classes[i]:
				p.cached.Add(-int64(b.cost))
				p.stack.memory.Add(-int64(b.cost))
				freed = true
			default:
				goto nextClass
			}
		}
	nextClass:
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
	for _, cache := range p.classes {
		for {
			select {
			case b := <-cache:
				p.cached.Add(-int64(b.cost))
				p.stack.memory.Add(-int64(b.cost))
			default:
				goto nextClass
			}
		}
	nextClass:
	}
}
