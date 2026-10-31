package lru

import (
	"strconv"
	"testing"
	"time"
)

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
