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
	lock     sync.Mutex
	mapping  map[interface{}]*list.Element
	timeout  time.Duration
}

//NewLru create new lru cache
func NewLru(capacity int, timeout time.Duration) *LRU {
	return &LRU{
		capacity: capacity,
		list:     list.New(),
		mapping:  make(map[interface{}]*list.Element),
		timeout:  timeout,
	}
}

func (l *LRU) Add(key, value interface{}) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if elem, ok := l.mapping[key]; ok {
		r := elem.Value.(*lruEntry)
		r.key = key
		r.data = value
		r.store = time.Now()
		l.list.MoveToFront(elem)
		return
	}

	if l.capacity == 0 || l.list.Len() < l.capacity {
		l.mapping[key] = l.list.PushFront(&lruEntry{
			key:   key,
			data:  value,
			store: time.Now(),
		})
		return
	}

	elem := l.list.Back()
	r := elem.Value.(*lruEntry)
	delete(l.mapping, r.key)
	r.key = key
	r.data = value
	r.store = time.Now()
	l.list.MoveToFront(elem)
	l.mapping[key] = elem
}

//Delete delete a key from cache
func (l *LRU) Delete(key interface{}) {
	l.lock.Lock()
	defer l.lock.Unlock()
	node, ok := l.mapping[key]
	if ok {
		delete(l.mapping, key)
		l.list.Remove(node)
	}
}

func (l *LRU) Load(key interface{}) (interface{}, bool) {
	l.lock.Lock()
	defer l.lock.Unlock()
	node, ok := l.mapping[key]
	if !ok {
		return nil, false
	}

	y, ok := node.Value.(*lruEntry)
	if !ok {
		return nil, false
	}

	if l.timeout != 0 && time.Since(y.store) >= l.timeout {
		delete(l.mapping, key)
		l.list.Remove(node)
		return nil, false
	}

	l.list.MoveToFront(node)
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
