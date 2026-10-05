package disk

import (
	"fmt"
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

// Setup and query generation are outside the timer. Unlike the older miss
// benchmark, these results measure lookup rather than fmt.Sprintf.
func BenchmarkLookup(b *testing.B) {
	for _, segments := range []int{0, 1, 3} {
		b.Run(fmt.Sprintf("segments=%d", segments), func(b *testing.B) {
			trie, err := NewTrie[string](b.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(1<<30))
			if err != nil {
				b.Fatal(err)
			}
			defer trie.Close()
			queries := make([]string, 10000)
			for index := range queries {
				queries[index] = fmt.Sprintf("host%d.group%d.example.com", index, index%100)
			}
			for part := range max(1, segments) {
				if err := trie.Insert("*.example.com", "suffix"); err != nil {
					b.Fatal(err)
				}
				for index := part; index < len(queries); index += max(1, segments) {
					if err := trie.Insert(queries[index], "exact"); err != nil {
						b.Fatal(err)
					}
				}
				if segments != 0 {
					if err := trie.Sync(); err != nil {
						b.Fatal(err)
					}
				}
			}
			for _, query := range []struct {
				name, key string
				count     int
			}{
				{"hit", queries[0], 2},
				{"wildcard", "missing.group0.example.com", 1},
				{"miss_root", "missing.invalid", 0},
				{"miss_deep", "host0.group0.example.net", 0},
			} {
				b.Run(query.name, func(b *testing.B) {
					if got := trie.Search(query.key); len(got) != query.count {
						b.Fatalf("Search = %v", got)
					}
					b.ReportAllocs()
					for index := 0; b.Loop(); index++ {
						key := query.key
						if query.name == "hit" {
							key = queries[index%len(queries)]
						}
						trie.Search(key)
					}
				})
			}
			b.Run("parallel_hit", func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for index := 0; pb.Next(); index++ {
						trie.Search(queries[index%len(queries)])
					}
				})
			})
		})
	}
}

// Each iteration builds a fresh, fixed-size index including Sync and automatic
// compaction, rather than eventually benchmarking duplicate inserts.
func BenchmarkBuild(b *testing.B) {
	for _, count := range []int{10000, 100000, 1000000} {
		b.Run(fmt.Sprintf("rules=%d", count), func(b *testing.B) {
			queries := make([]string, count)
			for index := range queries {
				queries[index] = fmt.Sprintf("host%d.group%d.example.com", index, index%100)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				b.StopTimer()
				trie, err := NewTrie[string](b.TempDir(), codec.UnsafeStringCodec{})
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				err = trie.Batch(func(yield func(string, string) bool) {
					for _, key := range queries {
						if !yield(key, "route-list") {
							return
						}
					}
				})
				if err != nil {
					b.Fatal(err)
				}
				if err := trie.Sync(); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				var bytes int64
				for _, file := range globSegments(trie.Dir()) {
					info, err := os.Stat(file)
					if err != nil {
						b.Fatal(err)
					}
					bytes += info.Size()
				}
				b.ReportMetric(float64(bytes)/float64(count), "disk-B/rule")
				if err := trie.Close(); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
		})
	}
}
