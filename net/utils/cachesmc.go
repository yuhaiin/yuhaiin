package utils

import (
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
