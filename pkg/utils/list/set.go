package list

import "sync"

type Set[T comparable] struct {
	data map[T]struct{}
	mu   sync.Mutex
}

func (q *Set[T]) Push(x T) {
	q.mu.Lock()
	q.data[x] = struct{}{}
	q.mu.Unlock()
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

func (q *Set[T]) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.data)
}

func (q *Set[T]) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	clear(q.data)
}

func (q *Set[T]) Range(ranger func(T) bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for k := range q.data {
		if !ranger(k) {
			break
		}
	}
}

func NewSet[T comparable]() *Set[T] {
	return &Set[T]{data: make(map[T]struct{})}
}
