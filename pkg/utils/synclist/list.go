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
	l    *list.List
	lock sync.RWMutex
}

func New[T any]() *SyncList[T] { return &SyncList[T]{l: list.New()} }

func (s *SyncList[T]) MoveToFront(e *Element[T]) {
	s.lock.Lock()
	defer s.lock.Unlock()
	e.e.Value = e.Value
	s.l.MoveToFront(e.e)
}

func (s *SyncList[T]) PushFront(v T) *Element[T] {
	s.lock.Lock()
	defer s.lock.Unlock()
	return &Element[T]{e: s.l.PushFront(v), Value: v}
}

func (s *SyncList[T]) PushBack(v T) *Element[T] {
	s.lock.Lock()
	defer s.lock.Unlock()
	return &Element[T]{e: s.l.PushBack(v), Value: v}
}

func (s *SyncList[T]) Remove(e *Element[T]) T {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.l.Remove(e.e)
	return e.Value
}

func (s *SyncList[T]) Back() *Element[T] {
	s.lock.RLock()
	defer s.lock.RUnlock()
	b := s.l.Back()
	if b == nil {
		return nil
	}
	return &Element[T]{e: b, Value: b.Value.(T)}
}

func (s *SyncList[T]) Front() *Element[T] {
	s.lock.RLock()
	defer s.lock.RUnlock()
	b := s.l.Front()
	if b == nil {
		return nil
	}
	return &Element[T]{e: b, Value: b.Value.(T)}
}

func (s *SyncList[T]) Len() int {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.l.Len()
}
