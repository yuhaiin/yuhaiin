package lru

import (
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/list"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type lruEntry[K, V any] struct {
	key    K
	data   V
	expire int64
}

func (e *lruEntry[K, V]) Clone() *lruEntry[K, V] {
	return &lruEntry[K, V]{
		key:  e.key,
		data: e.data,
	}
}

// LRU Least Recently Used
// it is not thread safe
type lru[K comparable, V any] struct {
	list *list.List[*lruEntry[K, V]]

	lastPopEntry  *lruEntry[K, V]
	onRemove      func(K, V)
	onValueUpdate func(old, new V)
	mapping       map[K]*list.Element[*lruEntry[K, V]]
	capacity      uint
	timeout       time.Duration
}

type Option[K comparable, V any] func(*lru[K, V])

func WithOnRemove[K comparable, V any](f func(K, V)) func(*lru[K, V]) {
	return func(l *lru[K, V]) {
		l.onRemove = f
	}
}

func WithDefaultTimeout[K comparable, V any](t time.Duration) func(*lru[K, V]) {
	return func(l *lru[K, V]) {
		l.timeout = t
	}
}

func WithCapacity[K comparable, V any](capacity uint) func(*lru[K, V]) {
	return func(l *lru[K, V]) {
		l.capacity = capacity
	}
}

// New create new lru cache
func newLru[K comparable, V any](options ...Option[K, V]) *lru[K, V] {
	l := &lru[K, V]{
		list:    list.NewList[*lruEntry[K, V]](),
		mapping: make(map[K]*list.Element[*lruEntry[K, V]]),
	}

	for _, o := range options {
		o(l)
	}

	return l
}

type AddOption[K, V any] func(*lruEntry[K, V])

func WithTimeout[K, V any](t time.Duration) AddOption[K, V] {
	return func(le *lruEntry[K, V]) {
		le.expire = system.CheapNowNano() + t.Nanoseconds()
	}
}

func (l *lru[K, V]) Add(key K, value V, opts ...AddOption[K, V]) {
	entry := &lruEntry[K, V]{
		key:  key,
		data: value,
	}

	for _, z := range opts {
		z(entry)
	}

	if l.timeout != 0 && entry.expire == 0 {
		entry.expire = system.CheapNowNano() + l.timeout.Nanoseconds()
	}

	if elem, ok := l.mapping[key]; ok {
		if l.onValueUpdate != nil {
			l.onValueUpdate(elem.Value().data, value)
		}
		l.list.MoveToFront(elem.SetValue(entry))
		return
	}

	if l.capacity == 0 || uint(l.list.Len()) < l.capacity {
		l.mapping[key] = l.list.PushFront(entry)
		return
	}

	elem := l.list.Back()
	l.lastPopEntry = elem.Value().Clone()
	delete(l.mapping, elem.Value().key)
	if l.onRemove != nil {
		l.onRemove(elem.Value().key, elem.Value().data)
	}

	l.list.MoveToFront(elem.SetValue(entry))
	l.mapping[key] = elem
}

func (l *lru[K, V]) Load(key K) (v V, ok bool) {
	v, _, ok = l.load(key, false, false)
	return
}

func (l *lru[K, V]) LoadOptimistic(key K) (v V, expired, ok bool) {
	return l.load(key, false, true)
}

func (l *lru[K, V]) load(key K, refresh, optimistic bool) (v V, expired, ok bool) {
	node, ok := l.mapping[key]
	if !ok {
		return
	}

	if node.Value().expire != 0 && system.CheapNowNano()-node.Value().expire > 0 {
		expired = true

		if !optimistic {
			delete(l.mapping, node.Value().key)
			if l.onRemove != nil {
				l.onRemove(node.Value().key, node.Value().data)
			}

			l.list.Remove(node)
			return v, true, false
		}
	}

	if refresh && l.timeout != 0 {
		node.Value().expire = system.CheapNowNano() + l.timeout.Nanoseconds()
	}

	l.list.MoveToFront(node)
	return node.Value().data, expired, true
}

func (l *lru[K, V]) LoadRefreshExpire(key K) (v V, ok bool) {
	v, _, ok = l.load(key, true, false)
	return
}

func (l *lru[K, V]) ClearExpired() {
	now := system.CheapNowNano()
	for k, v := range l.mapping {
		if v.Value().expire != 0 && now-v.Value().expire > 0 {
			delete(l.mapping, k)
			if l.onRemove != nil {
				l.onRemove(k, v.Value().data)
			}
			l.list.Remove(v)
		}
	}
}

// Delete a key from cache
func (l *lru[K, V]) Delete(key K) {
	x, ok := l.mapping[key]
	if !ok {
		return
	}

	delete(l.mapping, key)
	if l.onRemove != nil {
		l.onRemove(key, x.Value().data)
	}
	l.list.Remove(x)
}

func (l *lru[K, V]) Len() int {
	return l.list.Len()
}
