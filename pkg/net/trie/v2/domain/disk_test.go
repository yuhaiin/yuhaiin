package domain

import (
	"bufio"
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/cache/badger"
)

func setupTestDB(t testing.TB) (*DiskTrie[string], string) {
	dt, err := badger.New("test.db")
	if err != nil {
		t.Fatal(err)
	}
	return NewDiskTrie(dt, GobCodec[string]{}), "test.db"
}

func cleanupTestDB(dt *DiskTrie[string], dir string) {
	dt.root.Badger().Close()
	os.RemoveAll(dir)
}

func TestDiskTrie_BasicInsertAndSearch(t *testing.T) {
	dt, dir := setupTestDB(t)
	defer cleanupTestDB(dt, dir)

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

func TestDiskTrie_WildcardLogic(t *testing.T) {
	dt, dir := setupTestDB(t)
	defer cleanupTestDB(dt, dir)

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

func TestDiskTrie_MultiValues(t *testing.T) {
	dt, dir := setupTestDB(t)
	defer cleanupTestDB(dt, dir)

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

func TestDiskTrie_Remove(t *testing.T) {
	dt, dir := setupTestDB(t)
	defer cleanupTestDB(dt, dir)

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

func randomDomainParts(depth int) string {
	parts := make([]string, depth)
	tlds := []string{"com", "net", "org", "cn", "io"}
	parts[0] = tlds[rand.Intn(len(tlds))]
	for i := 1; i < depth; i++ {
		parts[i] = fmt.Sprintf("sub%d-%d", i, rand.Intn(1000))
	}
	return strings.Join(parts, ".")
}

func BenchmarkInsert(b *testing.B) {
	dt, dir := setupTestDB(b)
	defer cleanupTestDB(dt, dir)

	domains := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		domains[i] = randomDomainParts(4)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dt.Insert(newFqdnReader(domains[i]), "BenchmarkValue")
	}
}

func BenchmarkSearch_Hit(b *testing.B) {
	dt, dir := setupTestDB(b)
	defer cleanupTestDB(dt, dir)

	count := 100000
	domains := make([]string, count)
	for i := range count {
		domains[i] = randomDomainParts(4)
		dt.Insert(newFqdnReader(domains[i]), "Val")
	}

	for i := 0; b.Loop(); i++ {
		target := domains[i%count]
		dt.Search(newFqdnReader(target))
	}
}

func TestWrite(t *testing.T) {
	data, _ := os.ReadFile("68eddc3f9c83630ab4d2db603368b9c5352d98538771d7e99abc24a2d08c2c50")
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(bufio.ScanLines)
	dt, dir := setupTestDB(t)
	defer cleanupTestDB(dt, dir)

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

func TestInsert(t *testing.T) {
	dt, dir := setupTestDB(t)
	defer cleanupTestDB(dt, dir)

	if err := dt.Insert(newFqdnReader("*.gxlqkg.com"), "*.gxlqkg.com"); err != nil {
		t.Error(err)
	}

	if err := dt.Insert(newFqdnReader("gxlqkg.com"), "gxlqkg.com"); err != nil {
		t.Error(err)
	}

	res := dt.Search(newFqdnReader("gxlqkg.com"))
	t.Log(res)
}

func BenchmarkSearch_Miss(b *testing.B) {
	dt, dir := setupTestDB(b)
	defer cleanupTestDB(dt, dir)

	for i := 0; i < 5000; i++ {
		dt.Insert(newFqdnReader(randomDomainParts(4)), "Val")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dt.Search(newFqdnReader(randomDomainParts(5)))
	}
}
