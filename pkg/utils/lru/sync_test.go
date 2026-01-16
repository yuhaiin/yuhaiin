package lru

import (
	"fmt"
	"strconv"
	"testing"
)

func TestSyncLru(t *testing.T) {
	lru := NewSyncLru(WithCapacity[string, string](4))

	lru.Add("a", "a")
	lru.Add("b", "b")
	lru.Add("c", "c")
	lru.Add("d", "d")

	lru.Range(func(k, v string) bool {
		t.Log(k, v)
		return true
	})

	val, ok := lru.Load("a")
	t.Log(val, ok)

	fmt.Println()
	lru.Add("e", "e")
	lru.Add("f", "f")

	lru.Range(func(k, v string) bool {
		t.Log(k, v)
		return true
	})
}

func TestSyncReverseLru(t *testing.T) {
	lru := NewSyncReverseLru(WithLruOptions(WithCapacity[string, string](4)))

	lru.Add("a", "a")
	lru.Add("b", "b")
	lru.Add("c", "c")
	lru.Add("d", "d")

	lru.Range(func(s1, s2 string) {
		t.Log(s1, s2)
	})

	val, ok := lru.ReverseLoad("b")
	t.Log(val, ok)

	fmt.Println()
	lru.Add("e", "e")
	lru.Add("f", "f")

	lru.Range(func(s1, s2 string) {
		t.Log(s1, s2)
	})
}

func BenchmarkSyncLruAdd(b *testing.B) {
	lru := NewSyncLru(WithCapacity[string, string](1000))

	for i := 0; b.Loop(); i++ {
		lru.Add(strconv.Itoa(i), "value")
	}
}
