package set

import (
	"reflect"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type Set[T comparable] struct {
	*immutableSet[T]
}

func (q *Set[T]) Push(x T) {
	q.mu.Lock()
	q.data[x] = struct{}{}
	q.mu.Unlock()
}

func (s *Set[T]) Pop() (T, bool) {
	if s == nil || s.immutableSet == nil {
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
	if q == nil || q.immutableSet == nil {
		return
	}
	q.mu.Lock()
	clear(q.data)
	q.mu.Unlock()
}

func (s *Set[T]) Delete(x T) {
	if s == nil || s.immutableSet == nil {
		return
	}

	s.mu.Lock()
	delete(s.data, x)
	s.mu.Unlock()
}

func (s *Set[T]) Immutable() *ImmutableSet[T] {
	return &ImmutableSet[T]{s.immutableSet}
}

func NewSet[T comparable]() *Set[T] {
	return &Set[T]{newImmutableSet[T]()}
}

type immutableSet[T comparable] struct {
	data map[T]struct{}
	mu   sync.RWMutex
}

type ImmutableSet[T comparable] struct {
	*immutableSet[T]
}

func newImmutableSet[T comparable]() *immutableSet[T] {
	return &immutableSet[T]{data: make(map[T]struct{})}
}

func (s *immutableSet[T]) Has(x T) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	_, ok := s.data[x]
	s.mu.RUnlock()
	return ok
}
func (s *immutableSet[T]) ContainsAll(x ...T) bool {
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
func (s *immutableSet[T]) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	l := len(s.data)
	s.mu.RUnlock()

	return l
}

func (s *immutableSet[T]) Range(ranger func(T) bool) {
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

func (s *immutableSet[T]) Merge(other *Set[T]) {
	s.mu.Lock()
	other.mu.RLock()
	for k := range other.data {
		s.data[k] = struct{}{}
	}
	other.mu.RUnlock()
	s.mu.Unlock()
}

func NewImmutableSet[T comparable]() *ImmutableSet[T] {
	return &ImmutableSet[T]{newImmutableSet[T]()}
}

var emptyStore = syncmap.SyncMap[reflect.Type, any]{}

func EmptyImmutableSet[T comparable]() *ImmutableSet[T] {
	z, _, _ := emptyStore.LoadOrCreate(reflect.TypeFor[T](), func() (any, error) {
		return NewImmutableSet[T](), nil
	})

	return z.(*ImmutableSet[T])
}
