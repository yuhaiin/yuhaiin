package trie

import (
	"slices"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

func TestOptionalDiskCIDR(t *testing.T) {
	dir := t.TempDir()
	trie := NewTrie[string](WithMmapCIDR(dir), WithCodec(codec.UnsafeStringCodec{}))
	trie.Insert("10.0.0.0/8", "private")

	address, err := netapi.ParseAddressPort("tcp", "10.1.2.3", 80)
	if err != nil {
		t.Fatal(err)
	}
	if got := trie.SearchFqdn(address); !slices.Contains(got, "private") {
		t.Fatalf("disk CIDR SearchFqdn = %v", got)
	}
	if err := trie.Close(); err != nil {
		t.Fatal(err)
	}

	trie = NewTrie[string](WithMmapCIDR(dir), WithCodec(codec.UnsafeStringCodec{}))
	defer trie.Close()
	if got := trie.SearchFqdn(address); !slices.Contains(got, "private") {
		t.Fatalf("reopened disk CIDR SearchFqdn = %v", got)
	}

	// The default constructor remains memory-backed and does not require a
	// filesystem directory for CIDR rules.
	memoryTrie := NewTrie[string]()
	memoryTrie.Insert("192.168.0.0/16", "memory")
	memoryAddress, err := netapi.ParseAddressPort("tcp", "192.168.1.1", 80)
	if err != nil {
		t.Fatal(err)
	}
	if got := memoryTrie.SearchFqdn(memoryAddress); !slices.Contains(got, "memory") {
		t.Fatalf("default memory CIDR SearchFqdn = %v", got)
	}
}
