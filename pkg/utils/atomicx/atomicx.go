package atomicx

import "sync/atomic"

type Value[T any] struct {
	x atomic.Value
}

func NewValue[T any](x T) *Value[T] {
	v := &Value[T]{}
	v.x.Store(x)
	return v
}

func (v *Value[T]) Load() T {
	vv := v.x.Load()
	if vv == nil {
		return *new(T)
	}

	x, ok := vv.(T)
	if !ok {
		return *new(T)
	}

	return x
}

func (v *Value[T]) Store(x T) { v.x.Store(x) }

func (v *Value[T]) Swap(x T) T {
	vv := v.x.Swap(x)
	if vv == nil {
		return *new(T)
	}

	z, ok := vv.(T)
	if !ok {
		return *new(T)
	}

	return z
}

func (v *Value[T]) CompareAndSwap(old, new T) bool {
	return v.x.CompareAndSwap(old, new)
}
