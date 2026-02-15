package domain

import (
	"bufio"
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/cache/pebble"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestDiskPebbleTrie_Batch(t *testing.T) {
	dt, dir := setupPebbleTestDB(t)
	defer cleanupPebbleTestDB(dt, dir)

	// Existing data
	err := dt.Insert(newFqdnReader("com.google.www"), "0.0.0.0")
	assert.NoError(t, err)
	err = dt.Insert(newFqdnReader("com.google.www"), "5.0.0.0")
	assert.NoError(t, err)

	data := []struct {
		domain string
		val    string
	}{
		{"com.google.www", "1.1.1.1"},
		{"com.google.mail", "2.2.2.2"},
		{"org.example", "3.3.3.3"},
		{"org.example", "4.4.4.4"}, // duplicate domain with different value
	}

	seq := func(yield func(*fqdnReader, string) bool) {
		for _, item := range data {
			if !yield(newFqdnReader(item.domain), item.val) {
				return
			}
		}
	}

	err = dt.Batch(seq)
	if err != nil {
		t.Fatalf("Batch failed: %v", err)
	}

	checkData := map[string][]string{
		"com.google.www":  {"0.0.0.0", "5.0.0.0", "1.1.1.1"},
		"com.google.mail": {"2.2.2.2"},
		"org.example":     {"3.3.3.3", "4.4.4.4"},
	}

	for domain, expected := range checkData {
		res := dt.Search(newFqdnReader(domain))
		for _, e := range expected {
			if !slices.Contains(res, e) {
				t.Errorf("Domain %s should contain %s, but got %v", domain, e, res)
			}
		}
		if len(res) != len(expected) {
			t.Errorf("Domain %s expected %d values, got %d: %v", domain, len(expected), len(res), res)
		}
	}
}

func setupPebbleTestDB(t testing.TB) (*DiskPebbleTrie[string], string) {
	dt, err := pebble.New("test.db")
	if err != nil {
		t.Fatal(err)
	}
	return NewDiskPebbleTrie(dt, codec.UnsafeStringCodec{}), "test.db"
}

func cleanupPebbleTestDB(dt *DiskPebbleTrie[string], dir string) {
	dt.root.Pebble().Close()
	os.RemoveAll(dir)
}

func TestDiskPebbleTrie_BasicInsertAndSearch(t *testing.T) {
	dt, dir := setupPebbleTestDB(t)
	defer cleanupPebbleTestDB(dt, dir)

	domain := "com.google.www"
	val := "1.1.1.1"

	err := dt.Insert(newFqdnReader(domain), val)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	res := dt.Search(newFqdnReader(domain))
	if !slices.Contains(res, val) {
		t.Errorf("Expected %v to contain %v", res, val)
	}

	resEmpty := dt.Search(newFqdnReader("com.baidu.www"))
	if len(resEmpty) != 0 {
		t.Errorf("Expected empty result, got %v", resEmpty)
	}
}

func TestDiskPebbleTrie_WildcardLogic(t *testing.T) {
	dt, dir := setupPebbleTestDB(t)
	defer cleanupPebbleTestDB(dt, dir)

	dt.Insert(newFqdnReader("com.google.*"), "WildcardValue")
	dt.Insert(newFqdnReader("com.google.mail"), "MailValue")

	tests := []struct {
		domain string
		expect []string
	}{
		{"com.google.mail", []string{"MailValue"}},
		{"com.google.maps", []string{"WildcardValue"}},
		{"com.apple.www", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			res := dt.Search(newFqdnReader(tt.domain))
			found := false
			for _, e := range tt.expect {
				if slices.Contains(res, e) {
					found = true
					break
				}
			}
			if len(tt.expect) == 0 && len(res) == 0 {
				found = true
			}

			if !found {
				t.Errorf("Search(%s) = %v, want one of %v", tt.domain, res, tt.expect)
			}
		})
	}
}

func TestDiskPebbleTrie_MultiValues(t *testing.T) {
	dt, dir := setupPebbleTestDB(t)
	defer cleanupPebbleTestDB(dt, dir)

	domain := "com.server"
	dt.Insert(newFqdnReader(domain), "IP1")
	dt.Insert(newFqdnReader(domain), "IP2")

	res := dt.Search(newFqdnReader(domain))
	if len(res) != 2 {
		t.Errorf("Expected 2 values, got %d: %v", len(res), res)
	}
	if !slices.Contains(res, "IP1") || !slices.Contains(res, "IP2") {
		t.Errorf("Missing values")
	}
}

func TestDiskPebbleTrie_Remove(t *testing.T) {
	dt, dir := setupPebbleTestDB(t)
	defer cleanupPebbleTestDB(dt, dir)

	domain := "com.test.remove"
	val := "DeleteMe"
	valKeep := "KeepMe"

	dt.Insert(newFqdnReader(domain), val)
	dt.Insert(newFqdnReader(domain), valKeep)

	err := dt.Remove(newFqdnReader(domain), val)
	if err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	res := dt.Search(newFqdnReader(domain))
	if slices.Contains(res, val) {
		t.Error("Value should be removed")
	}
	if !slices.Contains(res, valKeep) {
		t.Error("Other value should remain")
	}

	dt.Remove(newFqdnReader(domain), valKeep)
	res = dt.Search(newFqdnReader(domain))
	if len(res) != 0 {
		t.Error("Node should be empty")
	}
}

/*
cpu: AMD Ryzen 5 5600G with Radeon Graphics
BenchmarkDiskTrie
BenchmarkDiskTrie/insert
BenchmarkDiskTrie/insert-12         	  100437	     12089 ns/op	    4233 B/op	      73 allocs/op
BenchmarkDiskTrie/search_hit
BenchmarkDiskTrie/search_hit-12     	   26109	     45395 ns/op	   28204 B/op	     488 allocs/op
BenchmarkDiskTrie/search_miss
BenchmarkDiskTrie/search_miss-12    	  402478	      2814 ns/op	    1629 B/op	      39 allocs/op

cpu: AMD Ryzen 5 5600G with Radeon Graphics
BenchmarkDiskTrie
BenchmarkDiskTrie/insert
BenchmarkDiskTrie/insert-12         	  399330	     14565 ns/op	     402 B/op	      10 allocs/op
BenchmarkDiskTrie/search_hit
BenchmarkDiskTrie/search_hit-12     	   43410	     27252 ns/op	    1126 B/op	      39 allocs/op
BenchmarkDiskTrie/search_miss
BenchmarkDiskTrie/search_miss-12    	  490711	      2269 ns/op	     251 B/op	      14 allocs/op
*/
func BenchmarkDiskPebbleTrie(b *testing.B) {
	b.Run("insert", func(b *testing.B) {
		dt, dir := setupPebbleTestDB(b)
		defer cleanupPebbleTestDB(dt, dir)

		domains := make([]string, b.N)
		for i := 0; i < b.N; i++ {
			domains[i] = randomDomainParts(4)
		}

		b.ResetTimer()
		for i := 0; b.Loop(); i++ {
			dt.Insert(newFqdnReader(domains[i%len(domains)]), "BenchmarkValue")
		}
	})

	b.Run("search hit", func(b *testing.B) {
		dt, _ := setupPebbleTestDB(b)

		count := 100000
		domains := make([]string, count)
		for i := range count {
			domains[i] = randomDomainParts(4)
			dt.Insert(newFqdnReader(domains[i]), "Val")
		}

		if err := dt.root.Pebble().Close(); err != nil {
			b.Fatal(err)
		}

		dt, dir := setupPebbleTestDB(b)
		defer cleanupPebbleTestDB(dt, dir)

		b.ResetTimer()

		for i := 0; b.Loop(); i++ {
			target := domains[i%count]
			dt.Search(newFqdnReader(target))
		}
	})

	b.Run("search miss", func(b *testing.B) {
		dt, dir := setupPebbleTestDB(b)
		defer cleanupPebbleTestDB(dt, dir)

		for i := 0; i < 5000; i++ {
			dt.Insert(newFqdnReader(randomDomainParts(4)), "Val")
		}

		b.ResetTimer()
		for b.Loop() {
			dt.Search(newFqdnReader(randomDomainParts(5)))
		}
	})
}

func TestPebbleWrite(t *testing.T) {
	data, _ := os.ReadFile("/home/asutorufa/.config/yuhaiin/rule_cache/4923704fe4b6c6cc660358416ca3ec14a3f67dc5e4c18123662db631e89de685")
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(bufio.ScanLines)
	dt, dir := setupPebbleTestDB(t)
	defer cleanupPebbleTestDB(dt, dir)

	for scanner.Scan() {
		txt := strings.TrimSpace(scanner.Text())
		if txt == "" {
			continue
		}
		if err := dt.Insert(newFqdnReader(txt), txt); err != nil {
			t.Error(err)
		}
	}

	res := dt.Search(newFqdnReader("gxlqkg.com"))
	t.Log(res)
}

func TestPebbleInsert(t *testing.T) {
	dt, dir := setupPebbleTestDB(t)
	defer cleanupPebbleTestDB(dt, dir)

	if err := dt.Insert(newFqdnReader("*.gxlqkg.com"), "*.gxlqkg.com"); err != nil {
		t.Error(err)
	}

	if err := dt.Insert(newFqdnReader("gxlqkg.com"), "gxlqkg.com"); err != nil {
		t.Error(err)
	}

	res := dt.Search(newFqdnReader("gxlqkg.com"))
	t.Log(res)
}
