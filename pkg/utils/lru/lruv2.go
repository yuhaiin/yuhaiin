package lru

import (
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/synclist"
)

// LRU Least Recently Used
// it is not thread safe
type lru[K comparable, V any] struct {
	list *synclist.List[*lruEntry[K, V]]

	lastPopEntry *lruEntry[K, V]
	onRemove     func(K, V)
	mapping      map[K]*synclist.Element[*lruEntry[K, V]]
	capacity     uint
	timeout      time.Duration
}

type Optionv2[K comparable, V any] func(*lru[K, V])

func WithOnRemovev2[K comparable, V any](f func(K, V)) func(*lru[K, V]) {
	return func(l *lru[K, V]) {
		l.onRemove = f
	}
}

func WithExpireTimeoutv2[K comparable, V any](t time.Duration) func(*lru[K, V]) {
	return func(l *lru[K, V]) {
		l.timeout = t
	}
}

func WithCapacityv2[K comparable, V any](capacity uint) func(*lru[K, V]) {
	return func(l *lru[K, V]) {
		l.capacity = capacity
	}
}

// New create new lru cache
func newLru[K comparable, V any](options ...Optionv2[K, V]) *lru[K, V] {
	l := &lru[K, V]{
		list:    synclist.NewList[*lruEntry[K, V]](),
		mapping: make(map[K]*synclist.Element[*lruEntry[K, V]]),
	}

	for _, o := range options {
		o(l)
	}

	return l
}

func (l *lru[K, V]) Add(key K, value V, opts ...AddOption) {
	o := &addOptions{}
	for _, z := range opts {
		z(o)
	}

	if l.timeout != 0 && o.expireTime.IsZero() {
		o.expireTime = time.Now().Add(l.timeout)
	}

	entry := &lruEntry[K, V]{
		key:    key,
		data:   value,
		expire: o.expireTime,
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
	l.lastPopEntry = elem.Value.Clone()
	delete(l.mapping, elem.Value.key)
	if l.onRemove != nil {
		l.onRemove(elem.Value.key, elem.Value.data)
	}

	l.list.MoveToFront(elem.SetValue(entry))
	l.mapping[key] = elem
}

func (l *lru[K, V]) LoadExpireTime(key K) (v V, expireTime time.Time, ok bool) {
	node, ok := l.mapping[key]
	if !ok {
		return
	}

	if !node.Value.expire.IsZero() && time.Now().After(node.Value.expire) {
		delete(l.mapping, node.Value.key)
		if l.onRemove != nil {
			l.onRemove(node.Value.key, node.Value.data)
		}

		l.list.Remove(node)
		return v, expireTime, false
	}

	l.list.MoveToFront(node)
	return node.Value.data, node.Value.expire, true
}

// Delete delete a key from cache
func (l *lru[K, V]) Delete(key K) {
	x, ok := l.mapping[key]
	if !ok {
		return
	}

	delete(l.mapping, key)
	if l.onRemove != nil {
		l.onRemove(key, x.Value.data)
	}
	l.list.Remove(x)
}
