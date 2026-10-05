package disk

import (
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

func TestTriePersistsOverlappingPrefixes(t *testing.T) {
	dir := t.TempDir()
	trie, err := NewTrie[string](dir, codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}

	trie.InsertCIDR(netip.MustParsePrefix("10.0.0.0/8"), "network")
	trie.InsertCIDR(netip.MustParsePrefix("10.1.0.0/16"), "subnet")
	trie.InsertCIDR(netip.MustParsePrefix("10.1.2.3/32"), "host")

	assertContainsAll(t, trie.SearchIP(net.ParseIP("10.1.2.3")), "network", "subnet", "host")
	assertContainsAll(t, trie.SearchIP(net.ParseIP("10.1.2.4")), "network", "subnet")
	assertContainsAll(t, trie.SearchIP(net.ParseIP("10.2.2.2")), "network")
	if got := trie.SearchIP(net.ParseIP("0a00::1")); slices.Contains(got, "network") {
		t.Fatalf("IPv4 prefix matched IPv6 address: %v", got)
	}

	if err := trie.Close(); err != nil {
		t.Fatal(err)
	}

	trie, err = NewTrie[string](dir, codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	assertContainsAll(t, trie.SearchIP(net.ParseIP("10.1.2.3")), "network", "subnet", "host")

	trie.RemoveCIDR(netip.MustParsePrefix("10.1.0.0/16"))
	if trie.memoryUsed >= trie.memoryLimit {
		t.Fatalf("RemoveCIDR left an oversized memory builder: used=%d limit=%d", trie.memoryUsed, trie.memoryLimit)
	}
	assertContainsAll(t, trie.SearchIP(net.ParseIP("10.1.2.3")), "network", "host")
	if got := trie.SearchIP(net.ParseIP("10.1.2.4")); !slices.Equal(got, []string{"network"}) {
		t.Fatalf("after RemoveCIDR = %v, want [network]", got)
	}
}

func TestTrieSupportsIPv6AndCompaction(t *testing.T) {
	dir := t.TempDir()
	trie, err := NewTrie[string](dir, codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()

	trie.InsertCIDR(netip.MustParsePrefix("2001:db8::/32"), "v6-network")
	trie.InsertCIDR(netip.MustParsePrefix("2001:db8:1::/48"), "v6-subnet")
	for index := range 8 {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(index)}), 32)
		trie.InsertCIDR(prefix, "v4-host")
	}

	assertContainsAll(t, trie.SearchIP(net.ParseIP("2001:db8:1::1")), "v6-network", "v6-subnet")
	assertContainsAll(t, trie.SearchIP(net.ParseIP("192.0.2.3")), "v4-host")
	if count := len(globSegments(dir)); count >= segmentCompactionThreshold {
		t.Fatalf("segment count = %d, want less than %d", count, segmentCompactionThreshold)
	}
}

func TestTrieMatchesIPv4MappedIPv6PrefixesAsIPv4(t *testing.T) {
	trie, err := NewTrie[string](t.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()

	trie.InsertIP(netip.MustParseAddr("::ffff:192.0.2.1"), 128, "mapped-host")
	trie.InsertCIDR(netip.MustParsePrefix("::ffff:198.51.100.0/120"), "mapped-subnet")

	assertContainsAll(t, trie.SearchIP(net.ParseIP("192.0.2.1")), "mapped-host")
	assertContainsAll(t, trie.SearchIP(net.ParseIP("198.51.100.42")), "mapped-subnet")
}

func TestTrieReturnsOverlappingPrefixesFromLeastToMostSpecific(t *testing.T) {
	trie, err := NewTrie[string](t.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()

	trie.InsertCIDR(netip.MustParsePrefix("10.1.0.0/16"), "subnet")
	trie.InsertCIDR(netip.MustParsePrefix("10.0.0.0/8"), "network")

	got := trie.SearchIP(net.ParseIP("10.1.2.3"))
	if !slices.Equal(got, []string{"network", "subnet"}) {
		t.Fatalf("SearchIP = %v, want [network subnet]", got)
	}
}

func assertContainsAll(t *testing.T, got []string, expected ...string) {
	t.Helper()
	for _, value := range expected {
		if !slices.Contains(got, value) {
			t.Errorf("values = %v, want %q", got, value)
		}
	}
}

func TestLookupMatchesMemoryAcrossFlushes(t *testing.T) {
	disk, err := NewTrie[string](t.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(1<<30))
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	memory, err := NewTrie[string](t.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(1<<30))
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	rng := rand.New(rand.NewPCG(3, 4))
	queries := []net.IP{net.ParseIP("0.0.0.0"), net.ParseIP("::"), net.ParseIP("192.0.2.1"), nil, {1, 2, 3}}
	for index := range 120 {
		var data [16]byte
		for i := range data {
			data[i] = byte(rng.IntN(256))
		}
		addr := netip.AddrFrom16(data)
		if index%2 == 0 {
			addr = netip.AddrFrom4([4]byte{10, data[1], data[2], data[3]})
		}
		prefix := netip.PrefixFrom(addr, rng.IntN(addr.BitLen()+1)).Masked()
		value := fmt.Sprintf("list%d", rng.IntN(4))
		disk.InsertCIDR(prefix, value)
		memory.InsertCIDR(prefix, value)
		queries = append(queries, net.IP(addr.AsSlice()), net.IP(prefix.Addr().AsSlice()))
		if index%10 == 9 {
			if err := disk.Sync(); err != nil {
				t.Fatal(err)
			}
		}
		for _, query := range queries {
			got, want := disk.SearchIP(query), memory.SearchIP(query)
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("SearchIP(%s) = %v, want %v", query, got, want)
			}
		}
	}
}

func TestSearchValuesSurviveClose(t *testing.T) {
	trie, err := NewTrie[string](t.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	trie.InsertCIDR(netip.MustParsePrefix("10.0.0.0/8"), "owned-value")
	got := trie.SearchIP(net.ParseIP("10.1.2.3"))
	if err := trie.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"owned-value"}) {
		t.Fatalf("Search after unmap = %v", got)
	}
}

func TestLargeCompactionAndReopen(t *testing.T) {
	dir := t.TempDir()
	trie, err := NewTrie[string](dir, codec.UnsafeStringCodec{}, WithMemoryLimit(32<<10))
	if err != nil {
		t.Fatal(err)
	}
	trie.InsertCIDR(netip.MustParsePrefix("10.0.0.0/8"), "network")
	for index := range 5000 {
		addr := netip.AddrFrom4([4]byte{10, 0, byte(index >> 8), byte(index)})
		trie.InsertCIDR(netip.PrefixFrom(addr, 32), fmt.Sprint(index))
	}
	if err := trie.Close(); err != nil {
		t.Fatal(err)
	}
	trie, err = NewTrie[string](dir, codec.UnsafeStringCodec{})
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	for index := range 5000 {
		ip := net.IP{10, 0, byte(index >> 8), byte(index)}
		if got := trie.SearchIP(ip); !slices.Equal(got, []string{"network", fmt.Sprint(index)}) {
			t.Fatalf("SearchIP(%s) = %v", ip, got)
		}
	}
}

func TestSingleIPv6PathIsCompressed(t *testing.T) {
	trie, err := NewTrie[string](t.TempDir(), codec.UnsafeStringCodec{})
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	trie.InsertCIDR(netip.MustParsePrefix("2001:db8:1234:5678::1/128"), "host")
	if err := trie.Sync(); err != nil {
		t.Fatal(err)
	}
	if count := trie.segments[0].nodeCnt; count > 3 {
		t.Fatalf("single IPv6 host uses %d disk nodes, want at most 3", count)
	}
	if got := trie.SearchIP(net.ParseIP("2001:db8:1234:5678::1")); !slices.Equal(got, []string{"host"}) {
		t.Fatalf("SearchIP = %v", got)
	}
	if got := trie.SearchIP(net.ParseIP("2001:db8:1234:5678::2")); len(got) != 0 {
		t.Fatalf("compressed path matched different host: %v", got)
	}
}

func TestLegacySegmentsMixCompactAndRemove(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile("testdata/legacy-v1.cidr")
	if err != nil {
		t.Fatal(err)
	}
	// This file was emitted by the actual v1 implementation before the change.
	if err := os.WriteFile(filepath.Join(dir, "segment-00000000000000000000.cidr"), data, 0600); err != nil {
		t.Fatal(err)
	}
	trie, err := NewTrie[string](dir, codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	if trie.segments[0].version != legacySegmentVersion {
		t.Fatal("fixture is not legacy")
	}
	check := func(ip string, want ...string) {
		t.Helper()
		if got := trie.SearchIP(net.ParseIP(ip)); !slices.Equal(got, want) {
			t.Fatalf("SearchIP(%s)=%v, want %v", ip, got, want)
		}
	}
	check("10.1.2.3", "v4-all", "network", "subnet", "host")
	check("2001:db8:1::1", "v6-all", "v6-network", "v6-subnet", "v6-host")
	trie.InsertCIDR(netip.MustParsePrefix("10.1.2.4/32"), "new-host")
	check("10.1.2.4", "v4-all", "network", "subnet", "new-host")
	trie.InsertCIDR(netip.MustParsePrefix("203.0.113.5/32"), "another")
	trie.InsertCIDR(netip.MustParsePrefix("2001:db8:1::2/128"), "new-v6")
	if len(trie.segments) != 1 || trie.segments[0].version != segmentVersion {
		t.Fatal("mixed segments did not compact to v2")
	}
	check("10.1.2.3", "v4-all", "network", "subnet", "host")
	check("2001:db8:1::2", "v6-all", "v6-network", "v6-subnet", "new-v6")
	trie.RemoveCIDR(netip.MustParsePrefix("10.1.0.0/16"))
	check("10.1.2.3", "v4-all", "network", "host")
	if err := trie.Close(); err != nil {
		t.Fatal(err)
	}
	trie, err = NewTrie[string](dir, codec.UnsafeStringCodec{})
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	check("10.1.2.3", "v4-all", "network", "host")
	check("2001:db8:1::1", "v6-all", "v6-network", "v6-subnet", "v6-host")
}

func TestCompressedPrefixBoundaries(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		base := netip.MustParseAddr("10.93.201.75")
		if v6 {
			base = netip.MustParseAddr("2001:db8:1234:5678:9abc:def0:1357:2468")
		}
		for bits := 0; bits <= base.BitLen(); bits++ {
			t.Run(fmt.Sprintf("v6=%v/bits=%d", v6, bits), func(t *testing.T) {
				trie, err := NewTrie[string](t.TempDir(), codec.UnsafeStringCodec{})
				if err != nil {
					t.Fatal(err)
				}
				defer trie.Close()
				prefix := netip.PrefixFrom(base, bits).Masked()
				trie.InsertCIDR(prefix, "prefix")
				if err := trie.Sync(); err != nil {
					t.Fatal(err)
				}
				if got := trie.SearchIP(base.AsSlice()); !slices.Equal(got, []string{"prefix"}) {
					t.Fatalf("matching prefix=%v", got)
				}
				// A mismatch anywhere within a skipped path must be rejected.
				for bit := range bits {
					data := append([]byte(nil), base.AsSlice()...)
					data[bit/8] ^= 1 << uint(7-bit%8)
					if got := trie.SearchIP(data); len(got) != 0 {
						t.Fatalf("bit %d mismatch matched %v", bit, got)
					}
				}
			})
		}
	}
}

func BenchmarkDiskTrie(b *testing.B) {
	b.Run("IPv4/Insert", func(b *testing.B) {
		prefixes, _ := benchmarkIPv4Data()
		trie, err := NewTrie[string](b.TempDir(), codec.UnsafeStringCodec{})
		if err != nil {
			b.Fatal(err)
		}
		defer trie.Close()

		b.ResetTimer()
		for index := 0; b.Loop(); index++ {
			trie.InsertCIDR(prefixes[index%len(prefixes)], "benchmark")
		}
	})

	b.Run("IPv4/Search", func(b *testing.B) {
		prefixes, ips := benchmarkIPv4Data()
		dir := b.TempDir()
		trie, err := NewTrie[string](dir, codec.UnsafeStringCodec{})
		if err != nil {
			b.Fatal(err)
		}
		for _, prefix := range prefixes {
			trie.InsertCIDR(prefix, "benchmark")
		}
		if err := trie.Sync(); err != nil {
			b.Fatal(err)
		}
		if err := trie.Close(); err != nil {
			b.Fatal(err)
		}
		trie, err = NewTrie[string](dir, codec.UnsafeStringCodec{})
		if err != nil {
			b.Fatal(err)
		}
		defer trie.Close()

		b.ResetTimer()
		for index := 0; b.Loop(); index++ {
			trie.SearchIP(ips[index%len(ips)])
		}
	})

	b.Run("IPv6/Insert", func(b *testing.B) {
		prefixes, _ := benchmarkIPv6Data()
		trie, err := NewTrie[string](b.TempDir(), codec.UnsafeStringCodec{})
		if err != nil {
			b.Fatal(err)
		}
		defer trie.Close()

		b.ResetTimer()
		for index := 0; b.Loop(); index++ {
			trie.InsertCIDR(prefixes[index%len(prefixes)], "benchmark")
		}
	})

	b.Run("IPv6/Search", func(b *testing.B) {
		prefixes, ips := benchmarkIPv6Data()
		trie, err := NewTrie[string](b.TempDir(), codec.UnsafeStringCodec{})
		if err != nil {
			b.Fatal(err)
		}
		for _, prefix := range prefixes {
			trie.InsertCIDR(prefix, "benchmark")
		}
		if err := trie.Sync(); err != nil {
			b.Fatal(err)
		}
		if err := trie.Close(); err != nil {
			b.Fatal(err)
		}
		dir := trie.Dir()
		trie, err = NewTrie[string](dir, codec.UnsafeStringCodec{})
		if err != nil {
			b.Fatal(err)
		}
		defer trie.Close()

		b.ResetTimer()
		for index := 0; b.Loop(); index++ {
			trie.SearchIP(ips[index%len(ips)])
		}
	})
}

func benchmarkIPv4Data() ([]netip.Prefix, []net.IP) {
	prefixes := make([]netip.Prefix, 1000)
	ips := make([]net.IP, 1000)
	for index := range prefixes {
		addr := netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 1})
		prefixes[index] = netip.PrefixFrom(addr, 32)
		ips[index] = net.IP(append([]byte(nil), addr.AsSlice()...))
	}
	return prefixes, ips
}

func benchmarkIPv6Data() ([]netip.Prefix, []net.IP) {
	prefixes := make([]netip.Prefix, 1000)
	ips := make([]net.IP, 1000)
	for index := range prefixes {
		var bytes [16]byte
		bytes[0], bytes[1] = 0x20, 0x01
		bytes[2], bytes[3] = 0x0d, 0xb8
		bytes[14] = byte(index >> 8)
		bytes[15] = byte(index)
		addr := netip.AddrFrom16(bytes)
		prefixes[index] = netip.PrefixFrom(addr, 128)
		ips[index] = net.IP(append([]byte(nil), addr.AsSlice()...))
	}
	return prefixes, ips
}
