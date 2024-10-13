package lru

import (
	"fmt"
	"testing"
)

func TestSyncLru(t *testing.T) {
	lru := NewSyncLru(func(l *lru[string, string]) {
		l.capacity = 4
	})

	lru.Add("a", "a")
	lru.Add("b", "b")
	lru.Add("c", "c")
	lru.Add("d", "d")

	for k, v := range lru.Range {
		t.Log(k, v)
	}

	t.Log(lru.Load("a"))

	fmt.Println()
	lru.Add("e", "e")
	lru.Add("f", "f")

	for k, v := range lru.Range {
		t.Log(k, v)
	}
}

func TestSyncReverseLru(t *testing.T) {
	lru := NewSyncReverseLru(WithLruOptions(func(l *lru[string, string]) {
		l.capacity = 4
	}))

	lru.Add("a", "a")
	lru.Add("b", "b")
	lru.Add("c", "c")
	lru.Add("d", "d")

	lru.Range(func(s1, s2 string) {
		t.Log(s1, s2)
	})

	t.Log(lru.ReverseLoad("b"))

	fmt.Println()
	lru.Add("e", "e")
	lru.Add("f", "f")

	lru.Range(func(s1, s2 string) {
		t.Log(s1, s2)
	})
}
