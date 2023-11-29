package ring

import "testing"

func TestRing(t *testing.T) {
	r := NewRing[int](9, func() int {
		return 1
	})

	r.r.Do(func(a any) {
		t.Log(a)
	})
}
