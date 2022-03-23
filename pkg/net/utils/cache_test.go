package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLru(t *testing.T) {
	l := NewLru[string, string](4, 0)

	l.Add("a", "a")
	l.Add("b", "b")
	l.Add("c", "c")

	c, ok := l.Load("b")
	assert.True(t, ok)
	assert.Equal(t, "b", c)

	c, ok = l.Load("a")
	assert.True(t, ok)
	assert.Equal(t, "a", c)

	c, ok = l.Load("c")
	assert.True(t, ok)
	assert.Equal(t, "c", c)

	l.Add("d", "d")
	l.Add("e", "e")

	_, ok = l.Load("b")
	assert.False(t, ok)
	_, ok = l.Load("a")
	assert.True(t, ok)
}

func BenchmarkNewLru(b *testing.B) {
	l := NewLru[string, string](100, 0*time.Minute)

	l.Add("a", "a")
	l.Add("b", "b")
	l.Add("c", "c")

	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			l.Load("a")
		}
	})
	// if i%3 == 0 {
	// l.Load("a")
	// } else if i%3 == 1 {
	// 	go l.Add("z", "z")
	// } else if i%3 == 2 {
	// 	go l.Load("z")
	// } else {
	// 	go l.Load("c")
	// }
}
