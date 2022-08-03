package utils

import (
	"container/list"
	"sync"
	"time"
)

type lruEntry[K, V any] struct {
	key   K
	data  V
	store time.Time
}

// LRU Least Recently Used
type LRU[K, V any] struct {
	capacity     int
	list         *list.List
	mapping      sync.Map
	valueMapping sync.Map
	timeout      time.Duration
	lock         sync.Mutex
}

// NewLru create new lru cache
func NewLru[K, V any](capacity int, timeout time.Duration) *LRU[K, V] {
	return &LRU[K, V]{
		capacity: capacity,
		list:     list.New(),
		timeout:  timeout,
	}
}

func (l *LRU[K, V]) Add(key K, value V) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if elem, ok := l.mapping.Load(key); ok {
		r := elem.(*list.Element).Value.(*lruEntry[K, V])
		r.key = key
		r.data = value
		r.store = time.Now()
		l.list.MoveToFront(elem.(*list.Element))
		return
	}

	if l.capacity == 0 || l.list.Len() < l.capacity {
		element := l.list.PushFront(&lruEntry[K, V]{
			key:   key,
			data:  value,
			store: time.Now(),
		})
		l.mapping.Store(key, element)
		l.valueMapping.Store(value, element)
		return
	}

	elem := l.list.Back()
	r := elem.Value.(*lruEntry[K, V])
	l.mapping.Delete(r.key)
	l.valueMapping.Delete(r.data)
	r.key = key
	r.data = value
	r.store = time.Now()
	l.list.MoveToFront(elem)
	l.mapping.Store(key, elem)
	l.valueMapping.Store(value, elem)
}

// Delete delete a key from cache
func (l *LRU[K, V]) Delete(key K) {
	v, ok := l.mapping.LoadAndDelete(key)
	if ok {
		l.valueMapping.Delete(v.(*list.Element).Value.(*lruEntry[K, V]).data)
	}
}

func (l *LRU[K, V]) Load(key K) (v V, ok bool) {
	l.lock.Lock()
	defer l.lock.Unlock()
	node, ok := l.mapping.Load(key)
	if !ok {
		return v, false
	}

	y, ok := node.(*list.Element).Value.(*lruEntry[K, V])
	if !ok {
		return v, false
	}

	if l.timeout != 0 && time.Since(y.store) >= l.timeout {
		l.mapping.Delete(key)
		l.valueMapping.Delete(y.data)
		l.list.Remove(node.(*list.Element))
		return v, false
	}

	l.list.MoveToFront(node.(*list.Element))
	return y.data, true
}

func (l *LRU[K, V]) ValueLoad(v V) (k K, ok bool) {
	l.lock.Lock()
	defer l.lock.Unlock()
	node, ok := l.valueMapping.Load(v)
	if !ok {
		return k, false
	}

	y, ok := node.(*list.Element).Value.(*lruEntry[K, V])
	if !ok {
		return k, false
	}

	if l.timeout != 0 && time.Since(y.store) >= l.timeout {
		l.valueMapping.Delete(v)
		l.mapping.Delete(y.key)
		l.list.Remove(node.(*list.Element))
		return k, false
	}

	l.list.MoveToFront(node.(*list.Element))
	return y.key, true
}

func (l *LRU[K, V]) ValueExist(key V) bool {
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
