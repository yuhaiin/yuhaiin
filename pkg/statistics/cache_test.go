package statistics

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
)

func TestCache(t *testing.T) {
	count := atomic.Uint64{}
	cc := NewTotalCache(&cache.MockCache{
		OnPut: func(k, v []byte) { count.Add(1) },
	})
	defer cc.Close()
	wg := sync.WaitGroup{}

	start := time.Now()

	for range 10 {
		wg.Go(func() {
			for i := range 10000000 {
				cc.AddDownload(uint64(i))
			}
		})
	}

	wg.Wait()

	t.Log(time.Since(start))
	t.Log(cc.LoadDownload(), count.Load(), cc.LoadDownload()/uint64(SyncThreshold))
}

func BenchmarkCache(b *testing.B) {
	count := atomic.Uint64{}
	cc := NewTotalCache(&cache.MockCache{
		OnPut: func(k, v []byte) { count.Add(1) },
	})
	defer cc.Close()

	for i := 0; b.Loop(); i++ {
		cc.AddDownload(uint64(i))
	}
}
