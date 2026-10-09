package route

import (
	"fmt"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// End-to-end host matcher lookup, including the v2 domain adapter and host
// lock. before uses Sync; after finishes the offline load with Optimize.
func BenchmarkHostMatcher(b *testing.B) {
	const count = 30000
	matcher := newHostTrie(b.TempDir(), true)
	defer matcher.Close()
	lists := &Lists{hostTrie: matcher}
	queries := make([]netapi.Address, count)
	keys := make([]string, count)
	for index := range keys {
		keys[index] = fmt.Sprintf("host%d.group%d.example.com", index, index%100)
		var err error
		queries[index], err = netapi.ParseAddressPort("tcp", keys[index], 443)
		if err != nil {
			b.Fatal(err)
		}
	}
	for part := range 3 {
		if err := matcher.Add(func(yield func(string) bool) {
			yield("*.example.com")
			for index := part; index < count; index += 3 {
				if !yield(keys[index]) {
					return
				}
			}
		}, "route-list"); err != nil {
			b.Fatal(err)
		}
		if err := matcher.Sync(); err != nil {
			b.Fatal(err)
		}
	}
	if optimizer, ok := any(matcher.trie).(interface{ Optimize() error }); ok {
		if err := optimizer.Optimize(); err != nil {
			b.Fatal(err)
		}
	}
	for _, query := range queries {
		if got := lists.SearchHost(b.Context(), query); len(got) != 1 {
			b.Fatalf("Search=%v", got)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; b.Loop(); index++ {
		lists.SearchHost(b.Context(), queries[index%count])
	}
}
