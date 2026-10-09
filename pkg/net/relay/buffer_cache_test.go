package relay

import (
	"bytes"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type cacheTestPool struct {
	pool.Pool
	mu       sync.Mutex
	gets     int
	puts     int
	returned chan struct{}
}

func (p *cacheTestPool) GetBytes(size int) []byte {
	p.mu.Lock()
	p.gets++
	p.mu.Unlock()
	return p.Pool.GetBytes(size)
}

func (p *cacheTestPool) PutBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0xa5 // Detect returning a buffer whose destination still uses it.
	}
	p.Pool.PutBytes(b)
	p.mu.Lock()
	p.puts++
	p.mu.Unlock()
	select {
	case p.returned <- struct{}{}:
	default:
	}
}

func observeCachePool(t *testing.T) *cacheTestPool {
	t.Helper()
	previous := pool.DefaultPool
	p := &cacheTestPool{Pool: previous, returned: make(chan struct{}, 16)}
	pool.DefaultPool = p
	t.Cleanup(func() { pool.DefaultPool = previous })
	return p
}

func (p *cacheTestPool) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gets, p.puts
}

func makeCacheIdle(c *relayBufferCache) {
	c.mu.Lock()
	c.active = false
	c.mu.Unlock()
}

func TestRelayBufferCacheReusesRecentBuffer(t *testing.T) {
	p := observeCachePool(t)
	c := newRelayBufferCache(16384, time.Hour)
	defer c.close()
	for range 100 {
		b := c.get()
		copy(b, "recent")
		c.release(b[:6])
	}
	if gets, puts := p.counts(); gets != 1 || puts != 0 {
		t.Fatalf("recent activity gets/puts=%d/%d", gets, puts)
	}
	c.close()
	c.expire() // A callback already dispatched before close must be harmless.
	if gets, puts := p.counts(); gets != 1 || puts != 1 {
		t.Fatalf("close gets/puts=%d/%d", gets, puts)
	}
}

func TestRelayBufferCacheActivityExtendsRetention(t *testing.T) {
	p := observeCachePool(t)
	c := newRelayBufferCache(16384, time.Hour)
	defer c.close()
	c.release(c.get())
	c.release(c.get()) // Activity during the first interval.
	c.expire()
	if _, puts := p.counts(); puts != 0 {
		t.Fatal("recent activity did not extend retention")
	}
	c.expire() // The next interval had no activity.
	if gets, puts := p.counts(); gets != 1 || puts != 1 {
		t.Fatalf("inactive interval gets/puts=%d/%d", gets, puts)
	}
}

type pausedCacheWriter struct {
	bytes.Buffer
	entered chan struct{}
	release chan struct{}
}

func (w *pausedCacheWriter) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return w.Buffer.Write(p)
}

func TestRelayBufferCacheExpiryDoesNotReturnLeasedBuffer(t *testing.T) {
	p := observeCachePool(t)
	c := newRelayBufferCache(16384, time.Hour)
	defer c.close()
	first := c.get()
	c.release(first)
	b := c.get()
	copy(b, "original")
	dst := &pausedCacheWriter{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_, err := writeRelayBuffer(dst, b[:8], c.release)
		done <- err
	}()
	unblock := sync.OnceFunc(func() { close(dst.release) })
	defer func() { unblock(); <-stopped }()
	<-dst.entered
	makeCacheIdle(c)
	var callbacks sync.WaitGroup
	for range 16 {
		callbacks.Go(func() {
			for range 16 {
				c.expire()
			}
		})
	}
	callbacks.Wait()
	if _, puts := p.counts(); puts != 0 {
		t.Error("expiry returned a buffer still held by destination Write")
	}
	unblock()
	if err := <-done; err != nil || dst.String() != "original" {
		t.Fatalf("destination data=%q/%v", dst.String(), err)
	}
	// Completing the write refreshes the TTL, even if its old timer expired.
	c.expire()
	if _, puts := p.counts(); puts != 0 {
		t.Error("expiry ignored activity from the completed write")
	}
	makeCacheIdle(c)
	c.expire()
	if _, puts := p.counts(); puts != 1 {
		t.Fatalf("idle expiry puts=%d", puts)
	}
	// Two callbacks and Close cannot return the same buffer a second time.
	c.expire()
	c.close()
	if _, puts := p.counts(); puts != 1 {
		t.Fatalf("duplicate return puts=%d", puts)
	}
}

func TestRelayBufferCacheTimerReleasesIdleBuffer(t *testing.T) {
	p := observeCachePool(t)
	c := newRelayBufferCache(16384, 5*time.Millisecond)
	defer c.close()
	c.release(c.get())
	select {
	case <-p.returned:
	case <-time.After(time.Second):
		t.Fatal("idle buffer was not released")
	}
	// Resuming after expiry creates a new lease and a new expiry timer.
	c.release(c.get())
	select {
	case <-p.returned:
	case <-time.After(time.Second):
		t.Fatal("resumed idle buffer was not released")
	}
	c.close()
	if gets, puts := p.counts(); gets != 2 || puts != 2 {
		t.Fatalf("timer/close gets/puts=%d/%d", gets, puts)
	}
}

// The cache policy can be exercised at long-idle and recent-idle boundaries
// without waiting a literal hour. Real burst traffic is benchmarked separately
// through the production counted pipe in statistics.
func BenchmarkRelayBufferCacheResume(b *testing.B) {
	for _, expired := range []bool{false, true} {
		mode := "RecentIdle"
		if expired {
			mode = "AfterTTLExpiry"
		}
		b.Run(mode, func(b *testing.B) {
			c := newRelayBufferCache(16384, time.Hour)
			defer c.close()
			c.release(c.get())
			b.ReportAllocs()
			for b.Loop() {
				b.StopTimer()
				if expired {
					makeCacheIdle(c)
					c.expire()
				}
				runtime.GC()
				runtime.GC()
				b.StartTimer()
				buf := c.get()
				buf[0] = 1
				c.release(buf)
			}
		})
	}
}
