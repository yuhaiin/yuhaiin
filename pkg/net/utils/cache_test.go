package utils

import (
	"testing"
	"time"
)

func TestLru(t *testing.T) {
	l := NewLru(4, 0)

	l.Add("a", "a")
	l.Add("b", "b")
	l.Add("c", "c")
	t.Log(l.Load("b"))
	t.Log(l.Load("a"))
	t.Log(l.Load("c"))
	l.Add("d", "d")
	l.Add("e", "e")
}
func BenchmarkNewLru(b *testing.B) {
	b.StopTimer()
	l := NewLru(100, 0*time.Minute)

	l.Add("a", "a")
	l.Add("b", "b")
	l.Add("c", "c")

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		// if i%3 == 0 {
		l.Load("a")
		// } else if i%3 == 1 {
		// 	go l.Add("z", "z")
		// } else if i%3 == 2 {
		// 	go l.Load("z")
		// } else {
		// 	go l.Load("c")
		// }
	}
}
