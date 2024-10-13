package lru

import (
	"sync"
)

type SyncLru[K comparable, V any] struct {
	lru *lru[K, V]

	mu sync.Mutex
}

func NewSyncLru[K comparable, V any](options ...Option[K, V]) *SyncLru[K, V] {
	return &SyncLru[K, V]{
		lru: newLru(options...),
	}
}

func (l *SyncLru[K, V]) Add(key K, value V, opts ...AddOption[K, V]) {
	l.mu.Lock()
	l.lru.Add(key, value, opts...)
	l.mu.Unlock()
}
func (l *SyncLru[K, V]) LoadOrAdd(key K, value func() V, opts ...AddOption[K, V]) (v V, ok bool) {
	l.mu.Lock()
	v, ok = l.lru.Load(key)
	if ok {
		l.mu.Unlock()
		return
	}

	v = value()
	l.lru.Add(key, v, opts...)
	l.mu.Unlock()

	return
}

func (l *SyncLru[K, V]) Delete(key K) {
	l.mu.Lock()
	l.lru.Delete(key)
	l.mu.Unlock()
}

func (l *SyncLru[K, V]) LoadRefreshExpire(key K) (v V, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.LoadRefreshExpire(key)
}

func (l *SyncLru[K, V]) Load(key K) (v V, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.Load(key)
}

func (l *SyncLru[K, V]) LoadOptimistically(key K) (v V, expired, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.LoadOptimistic(key)
}

func (l *SyncLru[K, V]) Range(ranger func(K, V) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for k, v := range l.lru.mapping {
		if !ranger(k, v.Value().data) {
			return
		}
	}
}

func (l *SyncLru[K, V]) ClearExpired() {
	l.mu.Lock()
	l.lru.ClearExpired()
	l.mu.Unlock()
}

func (l *SyncLru[K, V]) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.Len()
}
