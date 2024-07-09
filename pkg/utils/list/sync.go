package list

import (
	"container/list"
	"sync"
)

type SyncList[T any] struct {
	l  *list.List
	mu sync.RWMutex
}

func NewSyncList[T any]() *SyncList[T] { return &SyncList[T]{l: list.New()} }

func (s *SyncList[T]) MoveToFront(e *Element[T]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.e.Value = e.Value
	s.l.MoveToFront(e.e)
}

func (s *SyncList[T]) PushFront(v T) *Element[T] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &Element[T]{e: s.l.PushFront(v)}
}

func (s *SyncList[T]) PushBack(v T) *Element[T] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &Element[T]{e: s.l.PushBack(v)}
}

func (s *SyncList[T]) Remove(e *Element[T]) T {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.l.Remove(e.e)

	x, _ := e.e.Value.(T)
	return x
}

func (s *SyncList[T]) Back() *Element[T] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b := s.l.Back()
	if b == nil {
		return nil
	}
	return &Element[T]{e: b}
}

func (s *SyncList[T]) Front() *Element[T] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b := s.l.Front()
	if b == nil {
		return nil
	}
	return &Element[T]{e: b}
}

func (s *SyncList[T]) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.l.Len()
}
