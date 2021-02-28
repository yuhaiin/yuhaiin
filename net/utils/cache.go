package utils

import (
	"container/list"
	"sync"
	"time"
)

type CacheExtend struct {
	pool    Map
	timeout time.Duration
	Get     func(domain string) (interface{}, bool)
	Add     func(domain string, mark interface{})
}

type withTime struct {
	data  interface{}
	store time.Time
}

func NewCacheExtend(timeout time.Duration) *CacheExtend {
	n := &CacheExtend{}

	if timeout == 0 {
		n.Get = n.get
		n.Add = n.add
		return n
	}
	n.timeout = timeout
	n.Get = n.getTimeout
	n.Add = n.addTimeout
	return n
}

func (c *CacheExtend) get(domain string) (interface{}, bool) {
	return c.pool.Load(domain)
}

func (c *CacheExtend) add(domain string, mark interface{}) {
	if mark == nil {
		return
	}
	c.pool.Store(domain, mark)

	if c.pool.Length() < 800 {
		return
	}

	c.pool.Range(func(key, value interface{}) bool {
		c.pool.Delete(key)
		if c.pool.Length() <= 700 {
			return false
		}
		return true
	})
}

func (c *CacheExtend) getTimeout(domain string) (interface{}, bool) {
	data, ok := c.pool.Load(domain)
	if !ok {
		return nil, false
	}
	if time.Since(data.(withTime).store) > c.timeout {
		c.pool.Delete(domain)
		return nil, false
	}

	return data.(withTime).data, true
}

func (c *CacheExtend) addTimeout(domain string, mark interface{}) {
	if mark == nil {
		return
	}
	c.pool.Store(domain, withTime{data: mark, store: time.Now()})

	if c.pool.Length() < 800 {
		return
	}

	c.pool.Range(func(key, value interface{}) bool {
		c.pool.Delete(key)
		if c.pool.Length() <= 700 {
			return false
		}
		return true
	})
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
}

func NewLru(capacity int) *LRU {
	return &LRU{
		capacity: capacity,
		list:     list.New().Init(),
	}
}

func (l *LRU) Add(key, value interface{}) {
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

func (l *LRU) Delete(key interface{}) {
	node, ok := l.mapping.LoadAndDelete(key)
	if !ok {
		return
	}

	l.lock.Lock()
	defer l.lock.Unlock()
	l.list.Remove(node.(*list.Element))
}

func (l *LRU) Load(key interface{}) interface{} {
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
