package statistics

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSQLiteTotalCache(t *testing.T) {
	cc := NewSQLiteTotalCache(filepath.Join(t.TempDir(), "state.db"))
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
	t.Log(cc.LoadDownload(), cc.LoadDownload()/uint64(SyncThreshold))
}

func BenchmarkSQLiteTotalCache(b *testing.B) {
	cc := NewSQLiteTotalCache(filepath.Join(b.TempDir(), "state.db"))
	defer cc.Close()

	for i := range b.N {
		cc.AddDownload(uint64(i))
	}
}
