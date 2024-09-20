package ring

import "container/ring"

type SysRing[T any] struct {
	r *ring.Ring
}

func NewRing[T any](n int, initValue func() T) *SysRing[T] {
	r := ring.New(n)

	r.Value = initValue()
	for p := r.Next(); p != r; p = p.Next() {
		p.Value = initValue()
	}

	return &SysRing[T]{r: r}
}

func (r *SysRing[T]) Next() *SysRing[T] {
	rr := r.r.Next()

	return &SysRing[T]{
		r: rr,
	}
}

func (r *SysRing[T]) Value() T {
	v := r.r.Value
	return v.(T)
}
