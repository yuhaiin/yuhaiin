package utils

import (
	"reflect"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/synclist"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type options struct {
	expireTime time.Time
}

type Option func(*options)

func WithExpireTime(t time.Time) Option {
	return func(o *options) {
		o.expireTime = t
	}
}

type lruEntry[K, V any] struct {
	key    K
	data   V
	expire time.Time
}

// LRU Least Recently Used
type LRU[K comparable, V any] struct {
	capacity       uint
	list           *synclist.SyncList[*lruEntry[K, V]]
	mapping        syncmap.SyncMap[K, *synclist.Element[*lruEntry[K, V]]]
	reverseMapping syncmap.SyncMap[V, *synclist.Element[*lruEntry[K, V]]]
	valueHashable  bool
	timeout        time.Duration
}

// NewLru create new lru cache
func NewLru[K comparable, V any](capacity uint, timeout time.Duration) *LRU[K, V] {
	l := &LRU[K, V]{
		capacity: capacity,
		list:     synclist.New[*lruEntry[K, V]](),
		timeout:  timeout,
	}

	var t V
	l.valueHashable = reflect.TypeOf(t).Comparable()

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
}

func (l *LRU[K, V]) Add(key K, value V, opts ...Option) {
	o := &options{}
	for _, z := range opts {
		z(o)
	}

	if l.timeout != 0 && o.expireTime.Equal(time.Time{}) {
		o.expireTime = time.Now().Add(l.timeout)
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
	if l.timeout != 0 && time.Now().After(e.Value.expire) {
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

// Cache use map save history
type Cache[K comparable, V any] struct {
	number         int
	pool           syncmap.SyncMap[K, V]
	lastUpdateTime time.Time
}

// NewCache create new cache
func NewCache[K comparable, V any]() *Cache[K, V] {
	return &Cache[K, V]{
		number:         0,
		lastUpdateTime: time.Now(),
	}
}

// Get .
func (c *Cache[K, V]) Get(domain K) (V, bool) {
	return c.pool.Load(domain)
}

// Add .
func (c *Cache[K, V]) Add(domain K, mark V) {
	if c.number > 800 {
		tmp := 0
		c.pool.Range(func(key K, value V) bool {
			c.pool.Delete(key)
			if tmp >= 80 {
				return false
			}
			tmp++
			return true
		})
		c.number -= 80

		if time.Since(c.lastUpdateTime) >= time.Hour {
			number := 0
			c.pool.Range(func(key K, value V) bool {
				number++
				return true
			})
			c.number = number
			c.lastUpdateTime = time.Now()
		}
	}
	c.pool.Store(domain, mark)
	c.number++
}
