package utils

import (
	"container/list"
	"sync"
	"time"
)

type withTime struct {
	data  interface{}
	store time.Time
}

// Cache <-- use map save history
type cache struct {
	number         int
	pool           sync.Map
	lastUpdateTime time.Time
}

func NewCache() *cache {
	return &cache{
		number:         0,
		lastUpdateTime: time.Now(),
	}
}

func (c *cache) Get(domain string) (interface{}, bool) {
	return c.pool.Load(domain)
}

func (c *cache) Add(domain string, mark interface{}) {
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
	//log.Println(domain+" Add success,number", c.number)
}

type LRU struct {
	capacity int
	list     *list.List
	lock     sync.Mutex
	mapping  sync.Map
	timeout  time.Duration

	Add  func(key, value interface{})
	Load func(key interface{}) interface{}
}

func NewLru(capacity int, timeout time.Duration) *LRU {
	l := &LRU{
		capacity: capacity,
		list:     list.New().Init(),
		timeout:  timeout,
	}

	if timeout > 0 {
		l.Add = l.addWithTime
		l.Load = l.loadWithTime
	} else {
		l.Add = l.add
		l.Load = l.load
	}

	return l
}

func (l *LRU) add(key, value interface{}) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.list.Len() >= l.capacity {
		if l.capacity == 0 {
			return
		}
		l.mapping.Delete(l.list.Back())
		l.list.Remove(l.list.Back())
	}
	node := l.list.PushFront(value)
	l.mapping.Store(key, node)
}

func (l *LRU) addWithTime(key, value interface{}) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.list.Len() >= l.capacity {
		if l.capacity == 0 {
			return
		}

		l.mapping.Delete(l.list.Back())
		l.list.Remove(l.list.Back())
	}

	node := l.list.PushFront(withTime{
		data:  value,
		store: time.Now(),
	})

	l.mapping.Store(key, node)
}

func (l *LRU) Delete(key interface{}) {
	node, ok := l.mapping.LoadAndDelete(key)
	if !ok {
		return
	}

	l.lock.Lock()
	defer l.lock.Unlock()
	l.list.Remove(node.(*list.Element))
}

func (l *LRU) load(key interface{}) interface{} {
	node, ok := l.mapping.Load(key)
	if !ok {
		return nil
	}
	x, ok := node.(*list.Element)
	if !ok {
		return nil
	}

	l.lock.Lock()
	defer l.lock.Unlock()
	l.list.MoveToFront(x)
	return x.Value
}

func (l *LRU) loadWithTime(key interface{}) interface{} {
	node, ok := l.mapping.Load(key)
	if !ok {
		return nil
	}

	x, ok := node.(*list.Element)
	if !ok {
		return nil
	}

	y, ok := x.Value.(withTime)
	if !ok {
		return nil
	}

	l.lock.Unlock()
	defer l.lock.Unlock()
	if time.Since(y.store) >= l.timeout {
		l.mapping.Delete(key)
		l.list.Remove(x)
		return nil
	}

	l.list.MoveToFront(x)
	return y.data
}
