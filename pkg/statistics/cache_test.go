package statistics

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAtomicCache(t *testing.T) {
	download := atomic.Uint64{}
	wg := sync.WaitGroup{}

	start := time.Now()

	for range 10 {
		wg.Add(1)

		go func() {
			defer wg.Done()
			for i := range 10000000 {
				download.Add(uint64(i))
			}
		}()
	}

	wg.Wait()

	t.Log(time.Since(start))
}

func TestChannelCache(t *testing.T) {
	download := uint64(0)
	ch := make(chan uint64, 100)
	wg := sync.WaitGroup{}

	start := time.Now()

	for range 10 {
		wg.Add(1)

		go func() {
			defer wg.Done()
			for i := range 10000000 {
				ch <- uint64(i)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for v := range ch {
		download += v
	}

	t.Log(time.Since(start))
}
