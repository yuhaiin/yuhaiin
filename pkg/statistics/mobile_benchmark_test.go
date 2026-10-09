package statistics

import (
	"fmt"
	"strconv"
	"testing"
)

// Includes opening, closing, committing and querying each burst. Close and
// deferred cleanup are not used to hide pending writes outside the timer.
func BenchmarkMobileConnectionLifecycle(b *testing.B) {
	for _, burst := range []int{1, 32} {
		b.Run(fmt.Sprint(burst), func(b *testing.B) {
			c := NewSQLiteConnStore(b.TempDir()+"/state.db", nil)
			defer c.Close()
			if c.sqliteDB == nil {
				b.Fatal("SQLite store unavailable")
			}
			infos := make([]string, 8)
			for i := range infos {
				infos[i] = fmt.Sprintf("site-%d.example:443", i)
			}
			var id uint64
			b.ReportAllocs()
			for b.Loop() {
				for range burst {
					id++
					info := performanceInfo(id)
					info.Addr = infos[id%8]
					c.storeConnection(performanceConnection(id), info)
					c.Remove(id)
				}
				if _, err := c.AllHistory(b.Context()); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*burst), "ns/flow")
			var hits uint64
			for _, item := range c.history.Get().Items {
				n, err := strconv.ParseUint(item.Count, 10, 64)
				if err != nil {
					b.Fatal(err)
				}
				hits += n
			}
			if hits != uint64(b.N*burst) {
				b.Fatalf("persisted hits=%d, want %d", hits, b.N*burst)
			}
		})
	}
}
