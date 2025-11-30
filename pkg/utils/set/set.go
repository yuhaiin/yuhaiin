package set

import "sync"

type Set[T comparable] struct {
	data map[T]struct{}
	mu   sync.RWMutex
}

func (q *Set[T]) Push(x T) {
	q.mu.Lock()
	q.data[x] = struct{}{}
	q.mu.Unlock()
}

func (s *Set[T]) Has(x T) bool {
	s.mu.RLock()
	_, ok := s.data[x]
	s.mu.RUnlock()
	return ok
}
func (s *Set[T]) ContainsAll(x ...T) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, v := range x {
		if _, ok := s.data[v]; !ok {
			return false
		}
	}
	return true
}

func (s *Set[T]) Delete(x T) {
	s.mu.Lock()
	delete(s.data, x)
	s.mu.Unlock()
}

func (s *Set[T]) Pop() (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k := range s.data {
		delete(s.data, k)
		return k, true
	}

	return *new(T), false
}

func (s *Set[T]) Len() int {
	s.mu.RLock()
	l := len(s.data)
	s.mu.RUnlock()

	return l
}

func (q *Set[T]) Clear() {
	q.mu.Lock()
	clear(q.data)
	q.mu.Unlock()
}

func (s *Set[T]) Range(ranger func(T) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k := range s.data {
		if !ranger(k) {
			break
		}
	}
}

func (s *Set[T]) Merge(other *Set[T]) {
	s.mu.Lock()
	other.mu.RLock()
	for k := range other.data {
		s.data[k] = struct{}{}
	}
	other.mu.RUnlock()
	s.mu.Unlock()
}

func NewSet[T comparable]() *Set[T] {
	return &Set[T]{data: make(map[T]struct{})}
}
