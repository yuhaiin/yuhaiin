package syncmap

import (
	"sync"
)

type SyncMap[key comparable, value any] struct {
	data   sync.Map
	single single[key]
}

func (a *SyncMap[T1, T2]) Load(key T1) (r T2, _ bool) {
	v, ok := a.data.Load(key)
	if !ok {
		return r, false
	}
	return v.(T2), true
}

func (a *SyncMap[T1, T2]) Store(key T1, value T2) {
	a.data.Store(key, value)
}

func (a *SyncMap[T1, T2]) LoadOrStore(key T1, value T2) (r T2, _ bool) {
	v, ok := a.data.LoadOrStore(key, value)
	return v.(T2), ok
}

func (a *SyncMap[T1, T2]) LoadOrCreate(key T1, f func() (T2, error)) (r T2, _ bool, err error) {
	v, ok := a.data.Load(key)
	if ok {
		return v.(T2), true, nil
	}

	a.single.Do(key, func() {
		v, ok = a.data.Load(key)
		if ok {
			return
		}

		v, err = f()
		if err != nil {
			return
		}

		v, ok = a.data.LoadOrStore(key, v)
	})
	if err != nil {
		return
	}

	return v.(T2), ok, nil
}

func (a *SyncMap[T1, T2]) LoadAndDelete(key T1) (r T2, _ bool) {
	v, ok := a.data.LoadAndDelete(key)
	if !ok {
		return r, false
	}
	return v.(T2), true
}

func (a *SyncMap[T1, T2]) Delete(key T1) {
	a.data.Delete(key)
}

func (a *SyncMap[T1, T2]) Range(f func(key T1, value T2) bool) {
	a.data.Range(func(key, value any) bool {
		return f(key.(T1), value.(T2))
	})
}

func (a *SyncMap[T1, T2]) RangeValues(f func(value T2) bool) {
	a.data.Range(func(_, value any) bool {
		return f(value.(T2))
	})
}

func (a *SyncMap[T1, T2]) Swap(x T1, b T2) (T2, bool) {
	v, ok := a.data.Swap(x, b)
	if ok {
		return v.(T2), true
	}

	return *new(T2), false
}

func (a *SyncMap[T1, T2]) CompareAndSwap(key T1, old T2, new T2) (swapped bool) {
	return a.data.CompareAndSwap(key, old, new)
}

func (a *SyncMap[T1, T2]) CompareAndDelete(key T1, old T2) (deleted bool) {
	return a.data.CompareAndDelete(key, old)
}

func (a *SyncMap[T1, T2]) Clear() { a.data.Clear() }

type single[T comparable] struct {
	store map[T]*sync.Mutex
	mu    sync.RWMutex
}

func (s *single[T]) getMu(key T) (*sync.Mutex, func()) {
	var done = func() {}

	s.mu.RLock()
	if s.store != nil {
		if mu, ok := s.store[key]; ok {
			s.mu.RUnlock()
			return mu, done
		}
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store == nil {
		s.store = make(map[T]*sync.Mutex)
	}

	mu, ok := s.store[key]
	if ok {
		return mu, done
	}

	mu = &sync.Mutex{}
	s.store[key] = mu
	done = func() {
		s.mu.Lock()
		delete(s.store, key)
		s.mu.Unlock()
	}

	return mu, done
}

func (s *single[T]) Do(key T, f func()) {
	mu, done := s.getMu(key)
	defer done()

	mu.Lock()
	defer mu.Unlock()
	f()
}
