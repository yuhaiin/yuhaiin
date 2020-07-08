package common

import (
	"sync"
	"time"
)

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
