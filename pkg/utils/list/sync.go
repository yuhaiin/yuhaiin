package list

import (
	"sync"
)

type SyncList[T any] struct {
	l  *List[T]
	mu sync.RWMutex
}

func NewSyncList[T any]() *SyncList[T] { return &SyncList[T]{l: New[T]()} }

func (s *SyncList[T]) MoveToFront(e *Element[T]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.l.MoveToFront(e)
}

func (s *SyncList[T]) PushFront(v T) *Element[T] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.l.PushFront(v)
}

func (s *SyncList[T]) PushBack(v T) *Element[T] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.l.PushBack(v)
}

func (s *SyncList[T]) Remove(e *Element[T]) T {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.l.Remove(e)

	return e.Value
}

func (s *SyncList[T]) Back() *Element[T] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b := s.l.Back()
	if b == nil {
		return nil
	}
	return b
}

func (s *SyncList[T]) Front() *Element[T] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b := s.l.Front()
	if b == nil {
		return nil
	}
	return b
}

func (s *SyncList[T]) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.l.Len()
}
