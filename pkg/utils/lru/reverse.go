package lru

import (
	"sync"
)

type ReverseSyncLru[K, V comparable] struct {
	lru        *lru[K, V]
	reverseMap map[V]*K
	mu         sync.Mutex
}

func NewSyncReverseLru[K, V comparable](options ...Option[K, V]) *ReverseSyncLru[K, V] {
	x := &ReverseSyncLru[K, V]{
		reverseMap: make(map[V]*K),
	}
	x.lru = newLru(options...)

	onRemove := x.lru.onRemove
	x.lru.onRemove = func(k K, v V) {
		delete(x.reverseMap, v)
		if onRemove != nil {
			onRemove(k, v)
		}
	}

	return x
}

func (l *ReverseSyncLru[K, V]) Add(key K, value V, opts ...AddOption[K, V]) {
	l.mu.Lock()
	_, ok := l.reverseMap[value]
	if ok {
		l.lru.Delete(key)
	}
	l.lru.Add(key, value, opts...)
	l.reverseMap[value] = &key
	l.mu.Unlock()
}

func (l *ReverseSyncLru[K, V]) Delete(key K) {
	l.mu.Lock()
	l.lru.Delete(key)
	l.mu.Unlock()
}

func (l *ReverseSyncLru[K, V]) LoadRefreshExpire(key K) (v V, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.LoadRefreshExpire(key)
}

func (l *ReverseSyncLru[K, V]) Load(key K) (v V, ok bool) {
	l.mu.Lock()
	v, ok = l.lru.Load(key)
	l.mu.Unlock()
	return
}

func (l *ReverseSyncLru[K, V]) LoadOptimistic(key K) (v V, expired, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.LoadOptimistic(key)
}

func (l *ReverseSyncLru[K, V]) Range(ranger func(K, V)) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for k, v := range l.lru.mapping {
		ranger(k, v.Value().data)
	}
}

func (l *ReverseSyncLru[K, V]) ReverseLoad(v V) (k K, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	node, ok := l.reverseMap[v]
	if !ok {
		return k, false
	}

	l.lru.Load(*node)

	return *node, true
}

func (l *ReverseSyncLru[K, V]) ValueExist(key V) bool {
	l.mu.Lock()
	_, ok := l.reverseMap[key]
	l.mu.Unlock()
	return ok
}

func (l *ReverseSyncLru[K, V]) LastPopValue() (v V, _ bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	x := l.lru.lastPopEntry
	if x != nil {
		return x.data, true
	}
	return
}

func (l *ReverseSyncLru[K, V]) ClearExpired() {
	l.mu.Lock()
	l.lru.ClearExpired()
	l.mu.Unlock()
}
