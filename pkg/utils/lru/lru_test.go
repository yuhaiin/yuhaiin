package lru

import (
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestLru(t *testing.T) {
	l := NewSyncReverseLru(WithLruOptions(WithCapacity[string, string](4)))

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

	assert.Equal(t, true, l.ValueExist("a"))
	assert.Equal(t, false, l.ValueExist("b"))
	assert.Equal(t, true, l.ValueExist("c"))
	assert.Equal(t, true, l.ValueExist("d"))
	assert.Equal(t, true, l.ValueExist("e"))
}

func TestExpire(t *testing.T) {
	l := NewSyncReverseLru(WithLruOptions(WithCapacity[string, string](4)))

	l.Add("a", "a", WithTimeout[string, string](time.Second))

	_, ok := l.Load("a")
	assert.Equal(t, true, ok)

	time.Sleep(time.Second * 2)

	_, expired, ok := l.LoadOptimistic("a")
	assert.Equal(t, true, expired)
	assert.Equal(t, true, ok)

	_, ok = l.Load("a")
	assert.Equal(t, false, ok)
}

func BenchmarkNewLru(b *testing.B) {
	l := NewSyncReverseLru[string, string]()

	l.Add("a", "a")
	l.Add("b", "b")
	l.Add("c", "c")

	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			l.Load("a")
		}
	})
}

func TestRange(t *testing.T) {
	l := NewSyncLru(func(l *lru[string, string]) {
		l.capacity = 1000
	})

	l.Add("a", "a")
	l.Add("b", "b")
	l.Add("c", "c")
	l.Add("d", "d")

	l.Range(func(k, v string) bool {
		t.Log(k, v)
		return true
	})
}
