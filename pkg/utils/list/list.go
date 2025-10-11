package list

import (
	"container/list"
)

type Element[T any] struct {
	// The list to which this element belongs.
	e *list.Element
}

func (e *Element[T]) Next() *Element[T] {
	n := e.e.Next()
	if n == nil {
		return nil
	}

	return &Element[T]{e: n}
}

func (e *Element[T]) Prev() *Element[T] {
	p := e.e.Prev()
	if p == nil {
		return nil
	}

	return &Element[T]{e: p}
}

func (e *Element[T]) SetValue(t T) *Element[T] {
	e.e.Value = t
	return e
}

func (e *Element[T]) Value() T {
	x, _ := e.e.Value.(T)
	return x
}

type List[T any] struct {
	l *list.List
}

func New[T any]() *List[T] { return &List[T]{l: list.New()} }

func (s *List[T]) MoveToFront(e *Element[T]) {
	s.l.MoveToFront(e.e)
}

func (s *List[T]) MoveToBack(e *Element[T]) {
	s.l.MoveToBack(e.e)
}

func (s *List[T]) PushFront(v T) *Element[T] {
	return &Element[T]{e: s.l.PushFront(v)}
}

func (s *List[T]) PushBack(v T) *Element[T] {
	return &Element[T]{e: s.l.PushBack(v)}
}

func (s *List[T]) Remove(e *Element[T]) T {
	s.l.Remove(e.e)
	x, _ := e.e.Value.(T)
	return x
}

func (s *List[T]) Back() *Element[T] {
	b := s.l.Back()
	if b == nil {
		return nil
	}
	return &Element[T]{e: b}
}

func (s *List[T]) Front() *Element[T] {
	b := s.l.Front()
	if b == nil {
		return nil
	}
	return &Element[T]{e: b}
}

func (s *List[T]) Len() int {
	return s.l.Len()
}
