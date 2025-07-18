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
	defer s.mu.RUnlock()
	_, ok := s.data[x]
	return ok
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
	defer s.mu.RUnlock()
	return len(s.data)
}

func (q *Set[T]) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	clear(q.data)
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

func NewSet[T comparable]() *Set[T] {
	return &Set[T]{data: make(map[T]struct{})}
}
