package disk

import (
	"net"
	"net/netip"
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

func assertContainsAll(t *testing.T, got []string, expected ...string) {
	t.Helper()
	for _, value := range expected {
		if !slices.Contains(got, value) {
			t.Errorf("values = %v, want %q", got, value)
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
