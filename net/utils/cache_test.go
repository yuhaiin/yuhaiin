package utils

import (
	"testing"
	"time"
)

func TestNewCacheExtend(t *testing.T) {
	x := NewCacheExtend(time.Second * 5)
	x.Add("aa", "aa")
	t.Log(x.Get("aa"))
	t.Log(x.Get("aa"))
	t.Log(x.Get("aa"))
	t.Log(x.Get("aa"))
	time.Sleep(time.Second * 6)
	t.Log(x.Get("aa"))
}

func TestLru(t *testing.T) {
	l := NewLru(4)

	print := func() {
		x := l.list.Front()
		y := ""
		for x != nil {
			y += x.Value.(string) + " "
			x = x.Next()
		}
		t.Log(y)
	}
	l.Add("a", "a")
	l.Add("b", "b")
	l.Add("c", "c")
	t.Log(l.Load("b"))
	print()
	t.Log(l.Load("a"))
	print()
	t.Log(l.Load("c"))
	print()
	l.Add("d", "d")
	l.Add("e", "e")
	print()
}
