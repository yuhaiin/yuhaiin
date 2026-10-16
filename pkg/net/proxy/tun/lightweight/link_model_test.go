package lightweight

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestSerializationQueueExcludesPropagation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, _ := memoryPair()
		q := simulate(a, linkProfile{rtt: 100 * time.Millisecond, bytesPerSecond: 1_000_000, queue: 2, mtu: 1500})
		defer q.Close()
		for range 4 {
			q.enqueue(make([]byte, 1000), true)
		}
		if q.drops.Load() != 2 {
			t.Fatal("serialization queue failed to bound waiting packets")
		}
		time.Sleep(3 * time.Millisecond)
		// First two packets are still propagating, but serialization has finished.
		for range 2 {
			q.enqueue(make([]byte, 1000), true)
		}
		if q.drops.Load() != 2 {
			t.Fatalf("propagation was mistaken for queue occupancy: %d drops", q.drops.Load())
		}
	})
}
