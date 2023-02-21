package lru

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestLru(t *testing.T) {
	l := NewLru[string, string](4)

	l.Add("a", "a")
	l.Add("b", "b")
	l.Add("c", "c")

	c, ok := l.Load("b")
	assert.Equal(t, true, ok)
	assert.Equal(t, "b", c)

	c, ok = l.Load("a")
	assert.Equal(t, true, ok)
	assert.Equal(t, "a", c)

	c, ok = l.Load("c")
	assert.Equal(t, true, ok)
	assert.Equal(t, "c", c)

	l.Add("d", "d")
	l.Add("e", "e")

	_, ok = l.Load("b")
	assert.Equal(t, false, ok)
	_, ok = l.Load("a")
	assert.Equal(t, true, ok)

	t.Log(l.ValueExist("a"))
	t.Log(l.ValueExist("b"))
	t.Log(l.ValueExist("c"))
	t.Log(l.ValueExist("d"))
	t.Log(l.ValueExist("e"))
}

func BenchmarkNewLru(b *testing.B) {
	l := NewLru[string, string](100)

	l.Add("a", "a")
	l.Add("b", "b")
	l.Add("c", "c")

	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			l.Load("a")
		}
	})
}
