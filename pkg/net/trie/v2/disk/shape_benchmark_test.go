package disk

import (
	"fmt"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

func BenchmarkDomainShape(b *testing.B) {
	for _, shape := range []string{"exact", "suffix", "overlap"} {
		for _, segments := range []int{1, 3} {
			b.Run(fmt.Sprintf("%s/segments=%d", shape, segments), func(b *testing.B) {
				const count = 10000
				keys := make([]string, count)
				queries := make([]string, count)
				for index := range keys {
					keys[index] = fmt.Sprintf("site%d.%s", index, []string{"com", "cn", "net", "org", "co.uk", "com.cn"}[index%6])
					queries[index] = keys[index]
					if shape != "exact" {
						queries[index] = "api." + keys[index]
					}
				}
				trie, err := NewTrie[string](b.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(1<<30))
				if err != nil {
					b.Fatal(err)
				}
				defer trie.Close()
				for part := range segments {
					for index := part; index < count; index += segments {
						key := keys[index]
						if shape != "exact" {
							key = "*." + key
						}
						if err := trie.Insert(key, "geosite-regional-services"); err != nil {
							b.Fatal(err)
						}
						if shape == "overlap" {
							if err := trie.Insert(queries[index], "user-selected-proxy-route"); err != nil {
								b.Fatal(err)
							}
						}
					}
					if err := trie.Sync(); err != nil {
						b.Fatal(err)
					}
				}
				expected := 1
				if shape == "overlap" {
					expected = 2
				}
				for _, query := range queries {
					if got := trie.Search(query); len(got) != expected {
						b.Fatalf("Search(%s)=%v", query, got)
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				for index := 0; b.Loop(); index++ {
					trie.Search(queries[index%count])
				}
			})
		}
	}
}

func BenchmarkBuildOptimized(b *testing.B) {
	const count = 125000
	keys := make([]string, count)
	for index := range keys {
		keys[index] = fmt.Sprintf("host%d.group%d.example.com", index, index%100)
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
			for _, key := range keys {
				if !yield(key, "route-list") {
					return
				}
			}
		})
		if err != nil {
			b.Fatal(err)
		}
		if optimizer, ok := any(trie).(interface{ Optimize() error }); ok {
			err = optimizer.Optimize()
		} else {
			err = trie.Sync()
		}
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		b.ReportMetric(float64(len(trie.segments)), "segments")
		if got := trie.Search(keys[0]); len(got) != 1 {
			b.Fatalf("Search=%v", got)
		}
		if err := trie.Close(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

// The TLD and parent domain exist, but the final label does not. This reaches
// deeper nodes unlike a miss at an unknown TLD, and has no wildcard match.
func BenchmarkDomainLateMiss(b *testing.B) {
	for _, segments := range []int{1, 3} {
		b.Run(fmt.Sprintf("segments=%d", segments), func(b *testing.B) {
			const count = 10000
			keys := make([]string, count)
			queries := make([]string, count)
			for index := range keys {
				keys[index] = fmt.Sprintf("site%d.com", index)
				queries[index] = "missing." + keys[index]
			}
			trie, err := NewTrie[string](b.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(1<<30))
			if err != nil {
				b.Fatal(err)
			}
			defer trie.Close()
			for part := range segments {
				for index := part; index < count; index += segments {
					if err := trie.Insert(keys[index], "route-list"); err != nil {
						b.Fatal(err)
					}
				}
				if err := trie.Sync(); err != nil {
					b.Fatal(err)
				}
			}
			for _, query := range queries {
				if got := trie.Search(query); len(got) != 0 {
					b.Fatalf("Search=%v", got)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; b.Loop(); index++ {
				trie.Search(queries[index%count])
			}
		})
	}
}
