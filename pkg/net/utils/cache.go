package utils

import (
	"container/list"
	"sync"
	"time"
)

type withTime struct {
	key   interface{}
	data  interface{}
	store time.Time
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

//LRU Least Recently Used
type LRU struct {
	capacity int
	list     *list.List
	lock     sync.Mutex
	mapping  map[interface{}]interface{}
	timeout  time.Duration
}

//NewLru create new lru cache
func NewLru(capacity int, timeout time.Duration) *LRU {
	return &LRU{
		capacity: capacity,
		list:     list.New().Init(),
		mapping:  make(map[interface{}]interface{}),
		timeout:  timeout,
	}
}

func (l *LRU) Add(key, value interface{}) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l, ok := l.mapping[key].(*list.Element); ok {
		if r, ok := l.Value.(*withTime); ok {
			r.key = key
			r.data = value
			r.store = time.Now()
			return
		}
	}

	if l.list.Len() >= l.capacity {
		if l.capacity == 0 {
			return
		}

		if r, ok := l.list.Back().Value.(*withTime); ok {
			delete(l.mapping, r.key)
		}
		l.list.Remove(l.list.Back())
	}

	node := l.list.PushFront(&withTime{
		key:   key,
		data:  value,
		store: time.Now(),
	})

	l.mapping[key] = node
}

//Delete delete a key from cache
func (l *LRU) Delete(key interface{}) {
	l.lock.Lock()
	defer l.lock.Unlock()
	node, ok := l.mapping[key]
	if ok {
		delete(l.mapping, key)
	}
	l.list.Remove(node.(*list.Element))
}

func (l *LRU) Load(key interface{}) interface{} {
	l.lock.Lock()
	defer l.lock.Unlock()
	node, ok := l.mapping[key]
	if !ok {
		return nil
	}

	x, ok := node.(*list.Element)
	if !ok {
		return nil
	}

	y, ok := x.Value.(*withTime)
	if !ok {
		return nil
	}

	if l.timeout > 0 && time.Since(y.store) >= l.timeout {
		delete(l.mapping, key)
		l.list.Remove(x)
		return nil
	}

	l.list.MoveToFront(x)
	return y.data
}
