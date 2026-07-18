package disk

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

func TestTrieFlushesAcrossSegments(t *testing.T) {
	dir := t.TempDir()
	trie, err := NewTrie[string](dir, codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()

	if err := trie.Insert("*.example.com", "wildcard"); err != nil {
		t.Fatal(err)
	}
	if err := trie.Insert("a.example.com", "exact"); err != nil {
		t.Fatal(err)
	}
	if got := trie.Search("a.example.com"); !slices.Contains(got, "wildcard") || !slices.Contains(got, "exact") {
		t.Fatalf("cross-segment Search = %v", got)
	}
	if count := len(globSegments(dir)); count < 2 {
		t.Fatalf("segment count = %d, want at least 2", count)
	}
}

func TestTriePersistsAndRemoves(t *testing.T) {
	dir := t.TempDir()
	trie, err := NewTrie[string](dir, codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := trie.Insert("*.example.com", "wildcard"); err != nil {
		t.Fatal(err)
	}
	if err := trie.Insert("a.example.com", "exact"); err != nil {
		t.Fatal(err)
	}
	if err := trie.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := trie.Close(); err != nil {
		t.Fatal(err)
	}

	trie, err = NewTrie[string](dir, codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	if got := trie.Search("a.example.com"); !slices.Contains(got, "wildcard") || !slices.Contains(got, "exact") {
		t.Fatalf("reopened Search = %v", got)
	}
	if err := trie.Remove("a.example.com", "exact"); err != nil {
		t.Fatal(err)
	}
	if got := trie.Search("a.example.com"); slices.Contains(got, "exact") || !slices.Contains(got, "wildcard") {
		t.Fatalf("after Remove Search = %v", got)
	}
	if err := trie.Clear(); err != nil {
		t.Fatal(err)
	}
	if got := trie.Search("a.example.com"); len(got) != 0 {
		t.Fatalf("after Clear Search = %v", got)
	}
	if len(globSegments(filepath.Clean(dir))) != 0 {
		t.Fatal("Clear left segment files")
	}
	if err := trie.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTrieCompactsSegments(t *testing.T) {
	dir := t.TempDir()
	trie, err := NewTrie[string](dir, codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if err := trie.Insert("host"+string(rune('a'+i))+".example.com", "value"); err != nil {
			t.Fatal(err)
		}
	}
	if count := len(globSegments(dir)); count >= 4 {
		t.Fatalf("segment count after compaction = %d", count)
	}
	if got := trie.Search("hosta.example.com"); !slices.Contains(got, "value") {
		t.Fatalf("compacted Search = %v", got)
	}
	if err := trie.Close(); err != nil {
		t.Fatal(err)
	}

	trie, err = NewTrie[string](dir, codec.UnsafeStringCodec{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	if got := trie.Search("hosth.example.com"); !slices.Contains(got, "value") {
		t.Fatalf("reopened compacted Search = %v", got)
	}
}

func TestTrieWildcardPatterns(t *testing.T) {
	trie, err := NewTrie[string](t.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(128))
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()

	patterns := []struct {
		pattern string
		mark    string
	}{
		{"*.baidu.com", "sub_baidu_test"},
		{"www.baidu.com", "test_baidu"},
		{"last.baidu.*", "test_last_baidu"},
		{"*.baidu.*", "last_sub_baidu_test"},
		{"spo.baidu.com", "test_no_sub_baidu"},
		{"www.google.com", "test_google"},
		{"163.com", "163"},
		{"*.google.com", "google"},
		{"*.dl.google.com", "google_dl"},
		{"api.sec.miui.*", "ad_miui"},
		{"*.miui.com", "miui"},
		{"*.x.*", "x_all"},
		{"*.x.com", "x_com"},
		{"www.x.*", "www_x"},
	}
	for _, item := range patterns {
		if err := trie.Insert(item.pattern, item.mark); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		domain string
		mark   string
	}{
		{"www.baidu.com", "test_baidu"},
		{"spo.baidu.com", "test_no_sub_baidu"},
		{"last.baidu.com.cn", "test_last_baidu"},
		{"test.baidu.com", "sub_baidu_test"},
		{"www.baidu.cn", "last_sub_baidu_test"},
		{"www.google.com", "test_google"},
		{"www.google.cn", ""},
		{"163.com", "163"},
		{"www.x.google.com", "google"},
		{"dl.google.com", "google_dl"},
		{"api.sec.miui.com", "miui"},
		{"a.x.x.net", "x_all"},
		{"a.x.com", "x_com"},
		{"www.x.z", "www_x"},
	}
	for _, test := range tests {
		got := trie.Search(test.domain)
		if test.mark == "" {
			if len(got) != 0 {
				t.Errorf("Search(%q) = %v, want empty", test.domain, got)
			}
			continue
		}
		if !slices.Contains(got, test.mark) {
			t.Errorf("Search(%q) = %v, want %q", test.domain, got, test.mark)
		}
	}
}

func BenchmarkDiskTrie(b *testing.B) {
	b.Run("insert", func(b *testing.B) {
		trie, err := NewTrie[string](b.TempDir(), codec.UnsafeStringCodec{})
		if err != nil {
			b.Fatal(err)
		}
		defer trie.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := trie.Insert(benchmarkDomain(i), "value"); err != nil {
				b.Fatal(err)
			}
		}
		if err := trie.Sync(); err != nil {
			b.Fatal(err)
		}
	})

	b.Run("search hit", func(b *testing.B) {
		dir := b.TempDir()
		trie, err := NewTrie[string](dir, codec.UnsafeStringCodec{})
		if err != nil {
			b.Fatal(err)
		}
		const count = 100000
		domains := make([]string, count)
		for i := range domains {
			domains[i] = benchmarkDomain(i)
			if err := trie.Insert(domains[i], "value"); err != nil {
				b.Fatal(err)
			}
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
		for i := 0; b.Loop(); i++ {
			trie.Search(domains[i%count])
		}
	})

	b.Run("search miss", func(b *testing.B) {
		trie, err := NewTrie[string](b.TempDir(), codec.UnsafeStringCodec{})
		if err != nil {
			b.Fatal(err)
		}
		defer trie.Close()
		for i := 0; i < 5000; i++ {
			if err := trie.Insert(benchmarkDomain(i), "value"); err != nil {
				b.Fatal(err)
			}
		}
		if err := trie.Sync(); err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for i := 0; b.Loop(); i++ {
			trie.Search(fmt.Sprintf("missing-%d.example.net", i))
		}
	})
}

func benchmarkDomain(i int) string {
	return strings.Join([]string{
		"com",
		fmt.Sprintf("sub1-%d", i%1000),
		fmt.Sprintf("sub2-%d", (i/1000)%1000),
		fmt.Sprintf("sub3-%d", i/1000000),
	}, ".")
}
