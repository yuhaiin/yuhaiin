package syncmap

import (
	"sync"
)

type SyncMap[key, value any] struct {
	data sync.Map
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

func (a *SyncMap[key, T2]) ValueSlice() (r []T2) {
	a.data.Range(func(key, value any) bool {
		r = append(r, value.(T2))
		return true
	})

	return r
}
