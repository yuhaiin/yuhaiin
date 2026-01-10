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

// 创建临时 DB
func setupTestDB(t testing.TB) (*DiskTrie[string], string) {
	dt, err := badger.New("test.db")
	if err != nil {
		t.Fatal(err)
	}
	return NewDiskTrie[string](dt), "test.db"
}

// 清理 DB
func cleanupTestDB(dt *DiskTrie[string], dir string) {
	dt.root.Badger().Close()
	// os.RemoveAll(dir)
}

// --- 单元测试 ---

func TestDiskTrie_BasicInsertAndSearch(t *testing.T) {
	dt, dir := setupTestDB(t)
	defer cleanupTestDB(dt, dir)

	// Case 1: 插入正常数据
	domain := "com.google.www"
	val := "1.1.1.1"

	err := dt.Insert(newFqdnReader(domain), val)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Case 2: 查找存在的数据
	res := dt.Search(newFqdnReader(domain))
	if !slices.Contains(res, val) {
		t.Errorf("Expected %v to contain %v", res, val)
	}

	// Case 3: 查找不存在的数据
	resEmpty := dt.Search(newFqdnReader("com.baidu.www"))
	if len(resEmpty) != 0 {
		t.Errorf("Expected empty result, got %v", resEmpty)
	}
}

func TestDiskTrie_WildcardLogic(t *testing.T) {
	dt, dir := setupTestDB(t)
	defer cleanupTestDB(dt, dir)

	// 插入 com.google.* -> "WildcardValue"
	// 对应 mockReader: ["com", "google", "*"]
	dt.Insert(newFqdnReader("com.google.*"), "WildcardValue")
	dt.Insert(newFqdnReader("com.google.mail"), "MailValue")

	tests := []struct {
		domain string
		expect []string
	}{
		// 你的 search 逻辑：如果精确匹配(mail)，会 goto _second，然后继续往后找
		// 如果是 com.google.mail，先匹配 com, google, mail (hit),
		// 然后 loop domain.next() (fail), return "MailValue" + 之前的通配符?
		// 让我们测试一下实际行为
		{"com.google.mail", []string{"MailValue"}},
		{"com.google.maps", []string{"WildcardValue"}}, // maps 不存在，触发 wildcard 回退逻辑
		{"com.apple.www", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			res := dt.Search(newFqdnReader(tt.domain))
			// 检查是否包含期望值
			// 注意：具体的 search 逻辑比较复杂，这里验证是否包含了我们期望的那个值即可
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

	// 同一个节点插入多个值
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

	// 删除其中一个值
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

	// 删除最后一个值，节点应该被清理 (虽然黑盒测试很难验证物理清理，但可以验证查不到了)
	dt.Remove(newFqdnReader(domain), valKeep)
	res = dt.Search(newFqdnReader(domain))
	if len(res) != 0 {
		t.Error("Node should be empty")
	}
}

// --- 基准测试 (Benchmarks) ---

// 生成随机域名 parts
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

	// 预生成数据避免计入 bench 时间
	domains := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		domains[i] = randomDomainParts(4) // 深度为4
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dt.Insert(newFqdnReader(domains[i]), "BenchmarkValue")
	}
}

func BenchmarkSearch_Hit(b *testing.B) {
	dt, dir := setupTestDB(b)
	defer cleanupTestDB(dt, dir)

	// 插入 10000 个基础数据
	count := 100000
	domains := make([]string, count)
	for i := range count {
		domains[i] = randomDomainParts(4)
		dt.Insert(newFqdnReader(domains[i]), "Val")
	}

	for i := 0; b.Loop(); i++ {
		// 随机取一个已存在的域名查找
		target := domains[i%count]
		dt.Search(newFqdnReader(target))
	}
}

func TestWrite(t *testing.T) {
	data, _ := os.ReadFile("/Library/Application Support/yuhaiin/rules/68eddc3f9c83630ab4d2db603368b9c5352d98538771d7e99abc24a2d08c2c50")
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

	// 插入数据
	for i := 0; i < 5000; i++ {
		dt.Insert(newFqdnReader(randomDomainParts(4)), "Val")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 生成全新的随机域名，极大概率 Miss
		dt.Search(newFqdnReader(randomDomainParts(5)))
	}
}
