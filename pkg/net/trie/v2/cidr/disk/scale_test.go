package disk

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

// Addresses have different /64 prefixes and long empty tails. Unlike a dense
// IPv4 range, this workload exercises both compressed branches and jump data.
func sparseIPv6Prefix(index int) netip.Prefix {
	var bytes [16]byte
	bytes[0], bytes[1], bytes[2], bytes[3] = 0x20, 0x01, 0x0d, 0xb8
	binary.BigEndian.PutUint32(bytes[4:8], uint32(index)*2654435761)
	bytes[15] = 1
	return netip.PrefixFrom(netip.AddrFrom16(bytes), 128)
}

func BenchmarkSparseIPv6Build(b *testing.B) {
	const count = 10000
	prefixes := make([]netip.Prefix, count)
	for index := range prefixes {
		prefixes[index] = sparseIPv6Prefix(index)
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
		var bytes int64
		for _, path := range globSegments(trie.Dir()) {
			info, err := os.Stat(path)
			if err != nil {
				b.Fatal(err)
			}
			bytes += info.Size()
		}
		b.ReportMetric(float64(bytes)/count, "disk-B/rule")
		for _, prefix := range prefixes {
			if got := trie.SearchIP(net.IP(prefix.Addr().AsSlice())); !slices.Equal(got, []string{"route-list"}) {
				b.Fatalf("Search(%s) = %v", prefix, got)
			}
		}
		if err := trie.Close(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

// A continuously querying reader overlaps 1,000 updates and synchronous
// compactions. Samples are capped to bound instrumentation memory; tail results
// are scheduler-sensitive and should not be treated as a latency guarantee.
func BenchmarkUpdateWithReader(b *testing.B) {
	for b.Loop() {
		b.StopTimer()
		trie, err := NewTrie[string](b.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(4096))
		if err != nil {
			b.Fatal(err)
		}
		trie.InsertCIDR(netip.MustParsePrefix("2001:db8::/32"), "stable")
		if err := trie.Sync(); err != nil {
			b.Fatal(err)
		}
		stop := make(chan struct{})
		done := make(chan []int64)
		ready := make(chan struct{})
		go func() {
			ip := net.ParseIP("2001:db8::2")
			samples := make([]int64, 0, 1<<20)
			close(ready)
			for {
				select {
				case <-stop:
					done <- samples
					return
				default:
				}
				start := time.Now()
				got := trie.SearchIP(ip)
				elapsed := time.Since(start).Nanoseconds()
				if !slices.Equal(got, []string{"stable"}) {
					b.Error("stable prefix changed")
				}
				if len(samples) < cap(samples) {
					samples = append(samples, elapsed)
				}
			}
		}()
		<-ready
		b.StartTimer()
		for index := range 1000 {
			trie.InsertCIDR(sparseIPv6Prefix(index), "updated")
		}
		err = trie.Sync()
		b.StopTimer()
		close(stop)
		samples := <-done
		if err != nil {
			b.Fatal(err)
		}
		if len(samples) == 0 || len(samples) == cap(samples) {
			b.Fatal("no samples or sample capacity exceeded")
		}
		slices.Sort(samples)
		b.ReportMetric(float64(samples[(len(samples)-1)*99/100]), "read-p99-ns")
		b.ReportMetric(float64(samples[len(samples)-1]), "read-max-ns")
		b.ReportMetric(float64(len(samples)), "read-samples")
		if err := trie.Close(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}
