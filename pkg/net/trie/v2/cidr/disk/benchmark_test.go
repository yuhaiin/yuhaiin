package disk

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

func BenchmarkLookup(b *testing.B) {
	for _, ipv6 := range []bool{false, true} {
		family := "IPv4"
		prefixes, ips := benchmarkIPv4Data()
		base := netip.MustParsePrefix("10.0.0.0/8")
		miss := net.ParseIP("192.0.2.1")
		if ipv6 {
			family = "IPv6"
			prefixes, ips = benchmarkIPv6Data()
			base = netip.MustParsePrefix("2001:db8::/32")
			miss = net.ParseIP("2001:db9::1")
		}
		for _, segments := range []int{0, 1, 3} {
			b.Run(fmt.Sprintf("%s/segments=%d", family, segments), func(b *testing.B) {
				trie, err := NewTrie[string](b.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(1<<30))
				if err != nil {
					b.Fatal(err)
				}
				defer trie.Close()
				for part := range max(1, segments) {
					trie.InsertCIDR(base, "network")
					for index := part; index < len(prefixes); index += max(1, segments) {
						trie.InsertCIDR(prefixes[index], "host")
					}
					if segments != 0 {
						if err := trie.Sync(); err != nil {
							b.Fatal(err)
						}
					}
				}
				b.Run("hit", func(b *testing.B) {
					if got := trie.SearchIP(ips[0]); len(got) != 2 {
						b.Fatalf("Search = %v", got)
					}
					b.ReportAllocs()
					for index := 0; b.Loop(); index++ {
						trie.SearchIP(ips[index%len(ips)])
					}
				})
				b.Run("miss", func(b *testing.B) {
					if got := trie.SearchIP(miss); len(got) != 0 {
						b.Fatalf("Search = %v", got)
					}
					b.ReportAllocs()
					for b.Loop() {
						trie.SearchIP(miss)
					}
				})
				b.Run("parallel_hit", func(b *testing.B) {
					b.ReportAllocs()
					b.RunParallel(func(pb *testing.PB) {
						for index := 0; pb.Next(); index++ {
							trie.SearchIP(ips[index%len(ips)])
						}
					})
				})
			})
		}
	}
}

func BenchmarkBuild(b *testing.B) {
	for _, count := range []int{10000, 100000, 1000000} {
		b.Run(fmt.Sprintf("rules=%d", count), func(b *testing.B) {
			prefixes := make([]netip.Prefix, count)
			for index := range prefixes {
				prefixes[index] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)}), 32)
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
				for _, prefix := range prefixes {
					trie.InsertCIDR(prefix, "route-list")
				}
				if err := trie.Sync(); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				files, err := filepath.Glob(filepath.Join(trie.Dir(), "segment-*.cidr"))
				if err != nil {
					b.Fatal(err)
				}
				var bytes int64
				for _, file := range files {
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
