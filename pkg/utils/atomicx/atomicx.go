package atomicx

import (
	"sync"
	"sync/atomic"
)

type Value[T any] struct {
	x  T
	mu sync.RWMutex
}

func NewValue[T any](x T) *Value[T] {
	return &Value[T]{x: x}
}

func (v *Value[T]) Load() T {
	v.mu.RLock()
	x := v.x
	v.mu.RUnlock()

	return x
}

func (v *Value[T]) Store(x T) {
	v.mu.Lock()
	v.x = x
	v.mu.Unlock()
}

func NewPointer[T any](x *T) *atomic.Pointer[T] {
	z := &atomic.Pointer[T]{}

	z.Store(x)

	return z
}
