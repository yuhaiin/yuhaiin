package lru

import (
	"fmt"
	"strconv"
	"testing"
	"time"
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

func TestSyncLruRangeWithExpiration(t *testing.T) {
	cache := NewSyncLru(WithCapacity[string, string](4))
	cache.Add("valid", "value", WithTimeout[string, string](100*time.Millisecond))
	cache.Add("expired", "value", WithTimeout[string, string](time.Nanosecond))
	time.Sleep(2 * time.Millisecond)

	var got string
	var expiresIn time.Duration
	cache.RangeWithExpiration(func(key, value string, remaining time.Duration) bool {
		got = key + "=" + value
		expiresIn = remaining
		return true
	})

	if got != "valid=value" {
		t.Fatalf("snapshot=%q, want valid entry", got)
	}
	if expiresIn <= 0 || expiresIn > 100*time.Millisecond {
		t.Fatalf("expiresIn=%s, want between 0 and 100ms", expiresIn)
	}
	if cache.Len() != 1 {
		t.Fatalf("cache length=%d, want 1 after removing expired entry", cache.Len())
	}
}
