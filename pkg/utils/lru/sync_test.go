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

	lru.Range(func(s1, s2 string) {
		t.Log(s1, s2)
	})

	t.Log(lru.LoadExpireTime("a"))

	fmt.Println()
	lru.Add("e", "e")
	lru.Add("f", "f")

	lru.Range(func(s1, s2 string) {
		t.Log(s1, s2)
	})
}

func TestSyncReverseLru(t *testing.T) {
	lru := NewSyncReverseLru(func(l *lru[string, string]) {
		l.capacity = 4
	})

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
