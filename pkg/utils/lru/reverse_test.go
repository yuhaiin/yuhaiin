package lru

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestReverseLru(t *testing.T) {
	lru := NewSyncReverseLru(WithLruOptions(func(l *lru[string, string]) {
		l.capacity = 4
	}), WithOnValueChanged[string](func(old, s string) {
		t.Log("on value remove", "new", s, "old", old)
	}))

	lru.Add("a", "a")
	lru.Add("a", "b")
	lru.Add("a", "c")
	lru.Add("a", "d")
	lru.Add("b", "a")
	lru.Add("c", "a")
	lru.Add("d", "a")
	lru.Add("e", "a")
	lru.Add("f", "a")

	assert.MustEqual(t, 2, len(lru.reverseMap))

	for _, v := range []struct {
		key  string
		want string
		ok   bool
	}{
		{"a", "d", true},
		{"b", "", false},
		{"c", "", false},
		{"d", "", false},
		{"e", "", false},
		{"f", "a", true},
	} {
		vv, ok := lru.Load(v.key)
		assert.Equal(t, v.ok, ok)
		if v.ok {
			assert.Equal(t, v.want, vv)
		}
	}
}
