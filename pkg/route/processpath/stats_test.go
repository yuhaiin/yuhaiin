package processpath

import (
	"fmt"
	"os"
	"runtime"
	"testing"
)

// TestIndexStatsReport prints index shape and retained heap for the pattern
// mix used by the route benchmarks. Run with PROCESSPATH_STATS=1 -v.
func TestIndexStatsReport(t *testing.T) {
	if os.Getenv("PROCESSPATH_STATS") == "" {
		t.Skip("set PROCESSPATH_STATS=1 to print index statistics")
	}
	for _, n := range []int{1, 10, 100, 1000, 10000} {
		for _, kind := range []string{"exact", "glob"} {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			b := NewBuilder(Linux)
			for i := range n {
				value := fmt.Sprintf("/opt/vendor%05d/bin/app", i)
				if kind == "glob" {
					value = []string{
						fmt.Sprintf("/opt/vendor%05d/**", i),
						fmt.Sprintf("**/pkg%05d/**", i),
						fmt.Sprintf("**/Example%05d*/bin/*", i),
						fmt.Sprintf("/usr/lib/app%05d/**/helper", i),
					}[i%4]
				}
				if _, err := b.Add(value, fmt.Sprintf("list%d", i%16)); err != nil {
					t.Fatal(err)
				}
			}
			ix := b.Build()
			runtime.GC()
			runtime.ReadMemStats(&after)
			s := ix.Stats()
			t.Logf("%-5s n=%-5d retained=%8dB (%5.0fB/entry) exact=%d globs=%d keys=%d maxBucket=%d fallback=%d avgSegments=%.2f avgLists=%.2f prefixLens=%d suffixLens=%d",
				kind, n, after.HeapAlloc-min(before.HeapAlloc, after.HeapAlloc), float64(after.HeapAlloc-min(before.HeapAlloc, after.HeapAlloc))/float64(n),
				s.Exact, s.Globs, s.Buckets, s.MaxBucket, s.Fallback, s.AvgGlobLen, s.AvgGlobRefs, s.PrefixLens, s.SuffixLens)
			runtime.KeepAlive(ix)
		}
	}
}
