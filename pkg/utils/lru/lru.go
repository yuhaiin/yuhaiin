package lru

import (
	"reflect"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/synclist"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type lruEntry[K, V any] struct {
	key    K
	data   V
	expire int64
}

// LRU Least Recently Used
type LRU[K comparable, V any] struct {
	capacity       uint
	list           *synclist.SyncList[*lruEntry[K, V]]
	mapping        syncmap.SyncMap[K, *synclist.Element[*lruEntry[K, V]]]
	reverseMapping syncmap.SyncMap[V, *synclist.Element[*lruEntry[K, V]]]
	valueHashable  bool
	timeout        time.Duration

	lastPopEntry *lruEntry[K, V]
	onRemove     func(K, V)
}
type Option[K comparable, V any] func(*LRU[K, V])

func WithOnRemove[K comparable, V any](f func(K, V)) func(*LRU[K, V]) {
	return func(l *LRU[K, V]) {
		l.onRemove = f
	}
}

func WithExpireTimeout[K comparable, V any](t time.Duration) func(*LRU[K, V]) {
	return func(l *LRU[K, V]) {
		l.timeout = t
	}
}

func WithCapacity[K comparable, V any](capacity uint) func(*LRU[K, V]) {
	return func(l *LRU[K, V]) {
		l.capacity = capacity
	}
}

// NewLru create new lru cache
func NewLru[K comparable, V any](options ...Option[K, V]) *LRU[K, V] {
	l := &LRU[K, V]{
		list: synclist.New[*lruEntry[K, V]](),
	}

	for _, o := range options {
		o(l)
	}

	var t V
	if tp := reflect.TypeOf(t); tp != nil {
		l.valueHashable = tp.Comparable()
	}

	return l
}

func (l *LRU[K, V]) store(v *lruEntry[K, V], le *synclist.Element[*lruEntry[K, V]]) {
	l.mapping.Store(v.key, le)
	if l.valueHashable {
		l.reverseMapping.Store(v.data, le)
	}
}

func (l *LRU[K, V]) delete(v *lruEntry[K, V]) {
	l.mapping.Delete(v.key)
	if l.valueHashable {
		l.reverseMapping.Delete(v.data)
	}
	if l.onRemove != nil {
		l.onRemove(v.key, v.data)
	}
}

type addOptions struct {
	expireTime int64
}

type AddOption func(*addOptions)

func WithExpireTimeUnix(t int64) AddOption {
	return func(o *addOptions) {
		o.expireTime = t
	}
}

func (l *LRU[K, V]) Add(key K, value V, opts ...AddOption) {
	o := &addOptions{}
	for _, z := range opts {
		z(o)
	}

	if l.timeout != 0 && o.expireTime <= 0 {
		o.expireTime = time.Now().Unix() + int64(l.timeout.Seconds())
	}

	entry := &lruEntry[K, V]{key, value, o.expireTime}

	if elem, ok := l.mapping.Load(key); ok {
		l.list.MoveToFront(elem.SetValue(entry))
		return
	}

	var elem *synclist.Element[*lruEntry[K, V]]

	if l.capacity == 0 || uint(l.list.Len()) < l.capacity {
		elem = l.list.PushFront(entry)
	} else {
		elem = l.list.Back()
		l.lastPopEntry = &lruEntry[K, V]{
			key:    elem.Value.key,
			data:   elem.Value.data,
			expire: elem.Value.expire,
		}
		l.delete(elem.Value)
		l.list.MoveToFront(elem.SetValue(entry))
	}

	l.store(entry, elem)
}

// Delete delete a key from cache
func (l *LRU[K, V]) Delete(key K) {
	v, ok := l.mapping.LoadAndDelete(key)
	if ok {
		l.delete(v.Value)
	}
}

func (l *LRU[K, V]) load(e *synclist.Element[*lruEntry[K, V]]) *lruEntry[K, V] {
	if l.timeout != 0 && e.Value.expire-time.Now().Unix() < 0 {
		l.delete(e.Value)
		l.list.Remove(e)
		return nil
	}

	l.list.MoveToFront(e)
	return e.Value
}

func (l *LRU[K, V]) Load(key K) (v V, ok bool) {
	node, ok := l.mapping.Load(key)
	if !ok {
		return v, false
	}

	if z := l.load(node); z != nil {
		return z.data, true
	}

	return v, false
}

func (l *LRU[K, V]) ReverseLoad(v V) (k K, ok bool) {
	if !l.valueHashable {
		return k, false
	}

	node, ok := l.reverseMapping.Load(v)
	if !ok {
		return k, false
	}

	if z := l.load(node); z != nil {
		return z.key, true
	}

	return k, false
}

func (l *LRU[K, V]) ValueExist(key V) bool {
	if !l.valueHashable {
		return false
	}
	_, ok := l.reverseMapping.Load(key)
	return ok
}

func (l *LRU[K, V]) LastPopValue() (v V, _ bool) {
	if l.lastPopEntry == nil {
		return v, false
	}

	return l.lastPopEntry.data, true
}

func (l *LRU[K, V]) Range(ranger func(K, V)) {
	l.mapping.Range(func(key K, value *synclist.Element[*lruEntry[K, V]]) bool {
		ranger(key, value.Value.data)
		return true
	})
}
