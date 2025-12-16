package set

import (
	"reflect"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type Set[T comparable] struct {
	*ImmutableSet[T]
}

func (q *Set[T]) Push(x T) {
	q.mu.Lock()
	q.data[x] = struct{}{}
	q.mu.Unlock()
}

func (s *Set[T]) Pop() (T, bool) {
if s == nil || s.ImmutableSet == nil {
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
	if q == nil {
		return
	}
	q.mu.Lock()
	clear(q.data)
	q.mu.Unlock()
}

func (s *Set[T]) Delete(x T) {
if s == nil || s.ImmutableSet == nil {
		return
	}

	s.mu.Lock()
	delete(s.data, x)
	s.mu.Unlock()
}

func NewSet[T comparable]() *Set[T] {
	return &Set[T]{NewImmutableSet[T]()}
}

type ImmutableSet[T comparable] struct {
	data map[T]struct{}
	mu   sync.RWMutex
}

func NewImmutableSet[T comparable]() *ImmutableSet[T] {
	return &ImmutableSet[T]{data: make(map[T]struct{})}
}

func (s *ImmutableSet[T]) Has(x T) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	_, ok := s.data[x]
	s.mu.RUnlock()
	return ok
}
func (s *ImmutableSet[T]) ContainsAll(x ...T) bool {
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
func (s *ImmutableSet[T]) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	l := len(s.data)
	s.mu.RUnlock()

	return l
}

func (s *ImmutableSet[T]) Range(ranger func(T) bool) {
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

func (s *ImmutableSet[T]) Merge(other *Set[T]) {
	s.mu.Lock()
	other.mu.RLock()
	for k := range other.data {
		s.data[k] = struct{}{}
	}
	other.mu.RUnlock()
	s.mu.Unlock()
}

var emptyStore = syncmap.SyncMap[reflect.Type, any]{}

func EmptyImmutableSet[T comparable]() *ImmutableSet[T] {
	z, _, _ := emptyStore.LoadOrCreate(reflect.TypeFor[T](), func() (any, error) {
		return NewImmutableSet[T](), nil
	})

	return z.(*ImmutableSet[T])
}
