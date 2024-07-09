package lru

import (
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/list"
)

type lruEntry[K, V any] struct {
	key    K
	data   V
	expire time.Time
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

	lastPopEntry *lruEntry[K, V]
	onRemove     func(K, V)
	mapping      map[K]*list.Element[*lruEntry[K, V]]
	capacity     uint
	timeout      time.Duration
}

type Option[K comparable, V any] func(*lru[K, V])

func WithOnRemove[K comparable, V any](f func(K, V)) func(*lru[K, V]) {
	return func(l *lru[K, V]) {
		l.onRemove = f
	}
}

func WithExpireTimeout[K comparable, V any](t time.Duration) func(*lru[K, V]) {
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

func WithExpireTime[K, V any](t time.Time) AddOption[K, V] {
	return func(le *lruEntry[K, V]) {
		le.expire = t
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

	if l.timeout != 0 && entry.expire.IsZero() {
		entry.expire = time.Now().Add(l.timeout)
	}

	if elem, ok := l.mapping[key]; ok {
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

func (l *lru[K, V]) LoadExpireTime(key K) (v V, expireTime time.Time, ok bool) {
	node, ok := l.mapping[key]
	if !ok {
		return
	}

	if !node.Value().expire.IsZero() && time.Now().After(node.Value().expire) {
		delete(l.mapping, node.Value().key)
		if l.onRemove != nil {
			l.onRemove(node.Value().key, node.Value().data)
		}

		l.list.Remove(node)
		return v, expireTime, false
	}

	l.list.MoveToFront(node)
	return node.Value().data, node.Value().expire, true
}

// Delete delete a key from cache
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
