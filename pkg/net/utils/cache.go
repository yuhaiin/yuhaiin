package utils

import (
	"container/list"
	"sync"
	"time"
)

type lruEntry struct {
	key   interface{}
	data  interface{}
	store time.Time
}

//LRU Least Recently Used
type LRU struct {
	capacity int
	list     *list.List
	mapping  sync.Map
	timeout  time.Duration
}

//NewLru create new lru cache
func NewLru(capacity int, timeout time.Duration) *LRU {
	return &LRU{
		capacity: capacity,
		list:     list.New(),
		timeout:  timeout,
	}
}

func (l *LRU) Add(key, value interface{}) {
	if elem, ok := l.mapping.Load(key); ok {
		r := elem.(*list.Element).Value.(*lruEntry)
		r.key = key
		r.data = value
		r.store = time.Now()
		l.list.MoveToFront(elem.(*list.Element))
		return
	}

	if l.capacity == 0 || l.list.Len() < l.capacity {
		l.mapping.Store(key, l.list.PushFront(&lruEntry{
			key:   key,
			data:  value,
			store: time.Now(),
		}))
		return
	}

	elem := l.list.Back()
	r := elem.Value.(*lruEntry)
	l.mapping.Delete(r.key)
	r.key = key
	r.data = value
	r.store = time.Now()
	l.list.MoveToFront(elem)
	l.mapping.Store(key, elem)
}

//Delete delete a key from cache
func (l *LRU) Delete(key interface{}) {
	l.mapping.LoadAndDelete(key)
}

func (l *LRU) Load(key interface{}) (interface{}, bool) {
	node, ok := l.mapping.Load(key)
	if !ok {
		return nil, false
	}

	y, ok := node.(*list.Element).Value.(*lruEntry)
	if !ok {
		return nil, false
	}

	if l.timeout != 0 && time.Since(y.store) >= l.timeout {
		l.mapping.Delete(key)
		l.list.Remove(node.(*list.Element))
		return nil, false
	}

	l.list.MoveToFront(node.(*list.Element))
	return y.data, true
}

// Cache use map save history
type Cache struct {
	number         int
	pool           sync.Map
	lastUpdateTime time.Time
}

//NewCache create new cache
func NewCache() *Cache {
	return &Cache{
		number:         0,
		lastUpdateTime: time.Now(),
	}
}

//Get .
func (c *Cache) Get(domain string) (interface{}, bool) {
	return c.pool.Load(domain)
}

//Add .
func (c *Cache) Add(domain string, mark interface{}) {
	if mark == nil {
		return
	}
	if c.number > 800 {
		tmp := 0
		c.pool.Range(func(key, value interface{}) bool {
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
			c.pool.Range(func(key, value interface{}) bool {
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
