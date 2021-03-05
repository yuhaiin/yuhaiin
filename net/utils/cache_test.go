package utils

import (
	"testing"
	"time"
)

func TestLru(t *testing.T) {
	l := NewLru(4, 0)

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

func BenchmarkNewLru(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	l := NewLru(100, 10*time.Minute)

	l.Add("a", "a")
	l.Add("b", "b")
	l.Add("c", "c")

	for i := 0; i < b.N; i++ {
		if i%3 == 0 {
			go l.load("a")
		} else if i%3 == 1 {
			go l.Add("z", "z")
		} else if i%3 == 2 {
			go l.load("z")
		} else {
			go l.Load("c")
		}
	}
}
