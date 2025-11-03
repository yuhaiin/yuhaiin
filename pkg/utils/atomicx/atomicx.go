package atomicx

import (
	"sync/atomic"
)

type Value[T any] struct {
	a atomic.Pointer[T]
}

func NewValue[T any](x T) *Value[T] {
	a := &Value[T]{}

	a.Store(x)

	return a
}

func (v *Value[T]) Load() T {
	x := v.a.Load()
	if x == nil {
		return *new(T)
	}

	return *x
}

func (v *Value[T]) Store(x T) { v.a.Store(&x) }

func NewPointer[T any](x *T) *atomic.Pointer[T] {
	z := &atomic.Pointer[T]{}

	z.Store(x)

	return z
}

func PointerOrEmpty[T any](x *T) T {
	if x != nil {
		return *x
	}
	return *new(T)
}
