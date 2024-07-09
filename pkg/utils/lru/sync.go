package lru

import (
	"sync"
	"time"
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

func (l *SyncLru[K, V]) Delete(key K) {
	l.mu.Lock()
	l.lru.Delete(key)
	l.mu.Unlock()
}

func (l *SyncLru[K, V]) LoadExpireTime(key K) (v V, expireTime time.Time, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.LoadExpireTime(key)
}

func (l *SyncLru[K, V]) Load(key K) (v V, ok bool) {
	v, _, ok = l.LoadExpireTime(key)
	return
}

func (l *SyncLru[K, V]) Range(ranger func(K, V)) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for k, v := range l.lru.mapping {
		ranger(k, v.Value().data)
	}
}
