package ring

import "container/ring"

type Ring[T any] struct {
	r *ring.Ring
}

func NewRing[T any](n int, initValue func() T) *Ring[T] {
	r := ring.New(n)

	r.Value = initValue()
	for p := r.Next(); p != r; p = p.Next() {
		p.Value = initValue()
	}

	return &Ring[T]{r: r}
}

func (r *Ring[T]) Next() *Ring[T] {
	rr := r.r.Next()

	return &Ring[T]{
		r: rr,
	}
}

func (r *Ring[T]) Value() T {
	v := r.r.Value
	return v.(T)
}
