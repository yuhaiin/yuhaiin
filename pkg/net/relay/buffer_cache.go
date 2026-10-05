package relay

import (
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

const relayBufferIdleInterval = 30 * time.Second

// A relay owns its buffer while forwarding data and retains it briefly between
// chunks. Expiry may return only an idle buffer; it never touches a buffer held
// by ReadWithBuffer or the destination Write. The copy goroutine closes this
// cache after its last read/write, including while unwinding a panic.
// Idle expiry uses activity windows: after the first write the buffer expires
// in one interval; subsequent activity extends idle retention to one or two
// intervals. No clock read or timer reset is needed on the forwarding path.
type relayBufferCache struct {
	mu     sync.Mutex
	buffer []byte
	timer  *time.Timer
	active bool
	size   int
	ttl    time.Duration
	inUse  bool
	closed bool
}

func newRelayBufferCache(size int, ttl time.Duration) *relayBufferCache {
	return &relayBufferCache{size: size, ttl: ttl}
}

func (c *relayBufferCache) get() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		panic("relay: buffer cache is closed")
	}
	if c.buffer == nil {
		c.buffer = pool.GetBytes(c.size)
	}
	c.inUse = true
	return c.buffer
}

// End the current lease. The reader may return a shortened slice; the cache
// keeps ownership of the full allocation obtained by get. Only the copy
// goroutine calls get, release, and close; the timer can only call expire.
func (c *relayBufferCache) release([]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inUse = false
	if c.timer == nil {
		c.timer = time.AfterFunc(c.ttl, c.expire)
	} else {
		c.active = true
	}
}

func (c *relayBufferCache) expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.timer == nil {
		return
	}
	if c.inUse || c.active {
		// Observe activity in timeout-sized windows rather than reading a
		// clock and resetting a timer for every chunk. After later activity,
		// an idle buffer is returned within one to two timeout intervals.
		c.active = false
		c.timer.Reset(c.ttl)
		return
	}
	c.timer.Stop()
	pool.PutBytes(c.buffer)
	c.buffer = nil
	c.timer = nil
}

func (c *relayBufferCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	pool.PutBytes(c.buffer)
	c.buffer = nil
}
