package disk

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

func TestWildcardMetadataSurvivesCompaction(t *testing.T) {
	trie, err := NewTrie[string](t.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	for _, rule := range []struct{ key, mark string }{{"*.example.com", "suffix"}, {"www.example.com", "exact"}, {".example.com", "empty"}, {"*.other.com", "other"}} {
		if err := trie.Insert(rule.key, rule.mark); err != nil {
			t.Fatal(err)
		}
	}
	if len(trie.segments) != 1 {
		t.Fatalf("segments=%d", len(trie.segments))
	}
	segment := trie.segments[0]
	for index := range segment.nodeCnt {
		raw, ok := segment.region.BytesAt(segment.nodeOff+index*segmentNodeSize, segmentNodeSize)
		if !ok || binary.LittleEndian.Uint32(raw[12:])&(1<<31) == 0 {
			t.Fatalf("node %d lacks wildcard metadata", index)
		}
	}
	if got := trie.Search("www.example.com"); !slices.Equal(got, []string{"suffix", "exact"}) {
		t.Fatalf("Search = %v", got)
	}
	if got := trie.Search("missing.example.com"); !slices.Equal(got, []string{"suffix"}) {
		t.Fatalf("Search = %v", got)
	}
}

func TestOwnedMarksAvoidPerQueryCopy(t *testing.T) {
	trie, err := NewTrie[string](t.TempDir(), codec.UnsafeStringCodec{})
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	trie.Insert("*.example.com", "long-route-list-name")
	trie.Insert("www.example.com", "another-route-list-name")
	if err := trie.Sync(); err != nil {
		t.Fatal(err)
	}
	if allocs := testing.AllocsPerRun(100, func() { trie.Search("www.example.com") }); allocs > 2 {
		t.Fatalf("lookup allocates %g times, want at most 2", allocs)
	}
}

func TestLegacyWildcardMetadataMixesAndReopens(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile("testdata/legacy-v1.mmap")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "segment-00000000000000000000.mmap"), data, 0600); err != nil {
		t.Fatal(err)
	}
	trie, err := NewTrie[string](dir, codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	if got := trie.Search("www.example.com"); !slices.Equal(got, []string{"suffix", "exact"}) {
		t.Fatalf("legacy Search=%v", got)
	}
	for _, key := range []string{"one.test.com", "two.test.com", "three.test.com"} {
		if err := trie.Insert(key, "new"); err != nil {
			t.Fatal(err)
		}
	}
	if len(trie.segments) != 1 {
		t.Fatalf("segments=%d", len(trie.segments))
	}
	got := trie.Search("www.example.com")
	if err := trie.Remove("www.example.com", "exact"); err != nil {
		t.Fatal(err)
	}
	if err := trie.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"suffix", "exact"}) {
		t.Fatalf("unmapped values=%v", got)
	}
	trie, err = NewTrie[string](dir, codec.UnsafeStringCodec{})
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	if got := trie.Search("www.example.com"); !slices.Equal(got, []string{"suffix"}) {
		t.Fatalf("reopened Search=%v", got)
	}
	if got := trie.Search("one.test.com"); !slices.Equal(got, []string{"new"}) {
		t.Fatalf("new Search=%v", got)
	}
}

func TestOptimizePreservesOrderAndAllowsLaterUpdates(t *testing.T) {
	dir := t.TempDir()
	trie, err := NewTrie[string](dir, codec.UnsafeStringCodec{}, WithMemoryLimit(1<<30))
	if err != nil {
		t.Fatal(err)
	}
	for _, mark := range []string{"first", "second", "third"} {
		if err := trie.Insert("*.example.com", mark); err != nil {
			t.Fatal(err)
		}
		if err := trie.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	if len(trie.segments) != 3 {
		t.Fatalf("Sync segments=%d", len(trie.segments))
	}
	if err := trie.Optimize(); err != nil {
		t.Fatal(err)
	}
	if len(trie.segments) != 1 {
		t.Fatalf("Optimize segments=%d", len(trie.segments))
	}
	if err := trie.Insert("www.example.com", "fourth"); err != nil {
		t.Fatal(err)
	}
	if got := trie.Search("www.example.com"); !slices.Equal(got, []string{"first", "second", "third", "fourth"}) {
		t.Fatalf("Search=%v", got)
	}
	if err := trie.Close(); err != nil {
		t.Fatal(err)
	}
	trie, err = NewTrie[string](dir, codec.UnsafeStringCodec{})
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	if got := trie.Search("www.example.com"); !slices.Equal(got, []string{"first", "second", "third", "fourth"}) {
		t.Fatalf("reopened Search=%v", got)
	}
}

func TestSegmentViewsFallbackAndPoolBounds(t *testing.T) {
	trie, err := NewTrie[string](t.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(1<<30))
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	for index := range 1100 {
		if err := trie.Insert(fmt.Sprintf("host%d.example.com", index), fmt.Sprintf("unique-mark-%d", index)); err != nil {
			t.Fatal(err)
		}
	}
	if err := trie.Sync(); err != nil {
		t.Fatal(err)
	}
	segment := trie.segments[0]
	if segment.ownedValues {
		t.Fatal("unbounded mark dictionary")
	}
	// Exercise every section fallback path without allocating a whole section.
	segment.nodeData, segment.edgeData, segment.labelData, segment.valueData = nil, nil, nil, nil
	for index := range 1100 {
		if got := trie.Search(fmt.Sprintf("host%d.example.com", index)); !slices.Equal(got, []string{fmt.Sprintf("unique-mark-%d", index)}) {
			t.Fatalf("fallback Search=%v", got)
		}
	}
}
