package utils

import (
	"container/list"
	"reflect"
	"sync"
	"time"

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
	capacity      int
	list          *list.List
	mapping       syncmap.SyncMap[K, *list.Element]
	valueMapping  syncmap.SyncMap[V, *list.Element]
	valueHashable bool
	timeout       time.Duration
	lock          sync.Mutex
}

// NewLru create new lru cache
func NewLru[K comparable, V any](capacity int, timeout time.Duration) *LRU[K, V] {
	l := &LRU[K, V]{
		capacity: capacity,
		list:     list.New(),
		timeout:  timeout,
	}

	var t V
	l.valueHashable = reflect.TypeOf(t).Comparable()

	return l
}

func (l *LRU[K, V]) storeValueMapping(v V, le *list.Element) {
	if l.valueHashable {
		l.valueMapping.Store(v, le)
	}
}

func (l *LRU[K, V]) deleteValueMapping(v V) {
	if l.valueHashable {
		l.valueMapping.Delete(v)
	}
}

func (l *LRU[K, V]) Add(key K, value V, opts ...Option) {
	l.lock.Lock()
	defer l.lock.Unlock()

	o := &options{}
	for _, z := range opts {
		z(o)
	}

	if l.timeout != 0 && o.expireTime.Equal(time.Time{}) {
		o.expireTime = time.Now().Add(l.timeout)
	}

	if elem, ok := l.mapping.Load(key); ok {
		r := elem.Value.(*lruEntry[K, V])
		r.key = key
		r.data = value
		r.expire = o.expireTime
		l.list.MoveToFront(elem)
		return
	}

	if l.capacity == 0 || l.list.Len() < l.capacity {
		element := l.list.PushFront(&lruEntry[K, V]{
			key:    key,
			data:   value,
			expire: o.expireTime,
		})
		l.mapping.Store(key, element)
		l.storeValueMapping(value, element)
		return
	}

	elem := l.list.Back()
	r := elem.Value.(*lruEntry[K, V])
	l.mapping.Delete(r.key)
	l.deleteValueMapping(r.data)
	r.key = key
	r.data = value
	r.expire = o.expireTime
	l.list.MoveToFront(elem)
	l.mapping.Store(key, elem)
	l.storeValueMapping(value, elem)
}

// Delete delete a key from cache
func (l *LRU[K, V]) Delete(key K) {
	v, ok := l.mapping.LoadAndDelete(key)
	if ok {
		l.deleteValueMapping(v.Value.(*lruEntry[K, V]).data)
	}
}

func (l *LRU[K, V]) Load(key K) (v V, ok bool) {
	l.lock.Lock()
	defer l.lock.Unlock()
	node, ok := l.mapping.Load(key)
	if !ok {
		return v, false
	}

	y, ok := node.Value.(*lruEntry[K, V])
	if !ok {
		return v, false
	}

	if l.timeout != 0 && time.Now().After(y.expire) {
		l.mapping.Delete(key)
		l.deleteValueMapping(y.data)
		l.list.Remove(node)
		return v, false
	}

	l.list.MoveToFront(node)
	return y.data, true
}

func (l *LRU[K, V]) ValueLoad(v V) (k K, ok bool) {
	if !l.valueHashable {
		return k, false
	}

	l.lock.Lock()
	defer l.lock.Unlock()
	node, ok := l.valueMapping.Load(v)
	if !ok {
		return k, false
	}

	y, ok := node.Value.(*lruEntry[K, V])
	if !ok {
		return k, false
	}

	if l.timeout != 0 && time.Now().After(y.expire) {
		l.deleteValueMapping(v)
		l.mapping.Delete(y.key)
		l.list.Remove(node)
		return k, false
	}

	l.list.MoveToFront(node)
	return y.key, true
}

func (l *LRU[K, V]) ValueExist(key V) bool {
	if !l.valueHashable {
		return false
	}
	l.lock.Lock()
	defer l.lock.Unlock()
	_, ok := l.valueMapping.Load(key)
	return ok
}

// Cache use map save history
type Cache struct {
	number         int
	pool           sync.Map
	lastUpdateTime time.Time
}

// NewCache create new cache
func NewCache() *Cache {
	return &Cache{
		number:         0,
		lastUpdateTime: time.Now(),
	}
}

// Get .
func (c *Cache) Get(domain string) (any, bool) {
	return c.pool.Load(domain)
}

// Add .
func (c *Cache) Add(domain string, mark any) {
	if mark == nil {
		return
	}
	if c.number > 800 {
		tmp := 0
		c.pool.Range(func(key, value any) bool {
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
			c.pool.Range(func(key, value any) bool {
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
