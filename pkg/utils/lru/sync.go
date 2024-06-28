package lru

import (
	"sync"
	"time"
)

type Lru[K comparable, V any] struct {
	lru *lru[K, V]

	mu sync.Mutex
}

func NewSyncLru[K comparable, V any](options ...Optionv2[K, V]) *Lru[K, V] {
	return &Lru[K, V]{
		lru: newLru(options...),
	}
}

func (l *Lru[K, V]) Add(key K, value V, opts ...AddOption) {
	l.mu.Lock()
	l.lru.Add(key, value, opts...)
	l.mu.Unlock()
}

func (l *Lru[K, V]) Delete(key K) {
	l.mu.Lock()
	l.lru.Delete(key)
	l.mu.Unlock()
}

func (l *Lru[K, V]) LoadExpireTime(key K) (v V, expireTime time.Time, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.LoadExpireTime(key)
}

func (l *Lru[K, V]) Load(key K) (v V, ok bool) {
	v, _, ok = l.LoadExpireTime(key)
	return
}

func (l *Lru[K, V]) Range(ranger func(K, V)) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for k, v := range l.lru.mapping {
		ranger(k, v.Value.data)
	}
}
