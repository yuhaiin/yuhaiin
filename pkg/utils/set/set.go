package set

import (
	"reflect"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type baseSet[T comparable] struct {
	data map[T]struct{}
	mu   sync.RWMutex
}

func newBaseSet[T comparable]() *baseSet[T] {
	return &baseSet[T]{data: make(map[T]struct{})}
}

func (s *baseSet[T]) Has(x T) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	_, ok := s.data[x]
	s.mu.RUnlock()
	return ok
}

func (s *baseSet[T]) ContainsAll(x ...T) bool {
	if s == nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, v := range x {
		if _, ok := s.data[v]; !ok {
			return false
		}
	}
	return true
}

func (s *baseSet[T]) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	l := len(s.data)
	s.mu.RUnlock()

	return l
}

func (s *baseSet[T]) Range(ranger func(T) bool) {
	if s == nil {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k := range s.data {
		if !ranger(k) {
			break
		}
	}
}

func (s *baseSet[T]) merge(other *baseSet[T]) *baseSet[T] {
	if s == other || other.Len() == 0 {
		return s
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range other.Range {
		s.data[k] = struct{}{}
	}
	return s
}

type Set[T comparable] struct {
	*baseSet[T]
}

func (q *Set[T]) Push(x T) {
	q.mu.Lock()
	q.data[x] = struct{}{}
	q.mu.Unlock()
}

func (s *Set[T]) Pop() (T, bool) {
	if s == nil || s.baseSet == nil {
		return *new(T), false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for k := range s.data {
		delete(s.data, k)
		return k, true
	}

	return *new(T), false
}

func (q *Set[T]) Clear() {
	if q == nil || q.baseSet == nil {
		return
	}
	q.mu.Lock()
	clear(q.data)
	q.mu.Unlock()
}

func (s *Set[T]) Delete(x T) {
	if s == nil || s.baseSet == nil {
		return
	}

	s.mu.Lock()
	delete(s.data, x)
	s.mu.Unlock()
}

func (s *Set[T]) Immutable() *ImmutableSet[T] {
	return &ImmutableSet[T]{s.baseSet}
}

func (s *Set[T]) Merge(other *Set[T]) {
	s.merge(other.baseSet)
}

func NewSet[T comparable]() *Set[T] {
	return &Set[T]{newBaseSet[T]()}
}

type ImmutableSet[T comparable] struct {
	*baseSet[T]
}

func NewImmutableSet[T comparable]() *ImmutableSet[T] {
	return &ImmutableSet[T]{newBaseSet[T]()}
}

var emptyStore = syncmap.SyncMap[reflect.Type, any]{}

func EmptyImmutableSet[T comparable]() *ImmutableSet[T] {
	z, _, _ := emptyStore.LoadOrCreate(reflect.TypeFor[T](), func() (any, error) {
		return NewImmutableSet[T](), nil
	})

	return z.(*ImmutableSet[T])
}

func MergeImmutableSet[T comparable](sets ...*ImmutableSet[T]) *ImmutableSet[T] {
	if len(sets) == 0 {
		return EmptyImmutableSet[T]()
	}

	var base *baseSet[T]

	for _, v := range sets {
		if v == nil || v.baseSet == nil || v.Len() == 0 {
			continue
		}

		if base == nil {
			base = newBaseSet[T]()
		}

		base.merge(v.baseSet)
	}

	if base == nil {
		return EmptyImmutableSet[T]()
	}

	return &ImmutableSet[T]{base}
}
