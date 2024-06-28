package synclist

import (
	"container/list"
	"sync"
)

type Element[T any] struct {
	// The list to which this element belongs.
	e *list.Element

	// The value stored with this element.
	Value T
}

func (e *Element[T]) Next() *Element[T] {
	n := e.e.Next()
	if n == nil {
		return nil
	}

	return &Element[T]{e: n, Value: n.Value.(T)}
}

func (e *Element[T]) Prev() *Element[T] {
	p := e.e.Prev()
	if p == nil {
		return nil
	}

	return &Element[T]{e: p, Value: p.Value.(T)}
}

func (e *Element[T]) SetValue(t T) *Element[T] {
	e.Value = t
	return e
}

type SyncList[T any] struct {
	l  *list.List
	mu sync.RWMutex
}

func New[T any]() *SyncList[T] { return &SyncList[T]{l: list.New()} }

func (s *SyncList[T]) MoveToFront(e *Element[T]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.e.Value = e.Value
	s.l.MoveToFront(e.e)
}

func (s *SyncList[T]) PushFront(v T) *Element[T] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &Element[T]{e: s.l.PushFront(v), Value: v}
}

func (s *SyncList[T]) PushBack(v T) *Element[T] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &Element[T]{e: s.l.PushBack(v), Value: v}
}

func (s *SyncList[T]) Remove(e *Element[T]) T {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.l.Remove(e.e)
	return e.Value
}

func (s *SyncList[T]) Back() *Element[T] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b := s.l.Back()
	if b == nil {
		return nil
	}
	return &Element[T]{e: b, Value: b.Value.(T)}
}

func (s *SyncList[T]) Front() *Element[T] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b := s.l.Front()
	if b == nil {
		return nil
	}
	return &Element[T]{e: b, Value: b.Value.(T)}
}

func (s *SyncList[T]) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.l.Len()
}

type List[T any] struct {
	l *list.List
}

func NewList[T any]() *List[T] { return &List[T]{l: list.New()} }

func (s *List[T]) MoveToFront(e *Element[T]) {
	e.e.Value = e.Value
	s.l.MoveToFront(e.e)
}

func (s *List[T]) PushFront(v T) *Element[T] {
	return &Element[T]{e: s.l.PushFront(v), Value: v}
}

func (s *List[T]) PushBack(v T) *Element[T] {
	return &Element[T]{e: s.l.PushBack(v), Value: v}
}

func (s *List[T]) Remove(e *Element[T]) T {
	s.l.Remove(e.e)
	return e.Value
}

func (s *List[T]) Back() *Element[T] {
	b := s.l.Back()
	if b == nil {
		return nil
	}
	return &Element[T]{e: b, Value: b.Value.(T)}
}

func (s *List[T]) Front() *Element[T] {
	b := s.l.Front()
	if b == nil {
		return nil
	}
	return &Element[T]{e: b, Value: b.Value.(T)}
}

func (s *List[T]) Len() int {
	return s.l.Len()
}
