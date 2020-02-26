package dns

import (
	"sync"
	"time"
)

// Cache <-- use map save history
type Cache struct {
	number         int
	dns            sync.Map
	lastUpdateTime time.Time
}

func NewDnsCache() *Cache {
	return &Cache{
		number:         0,
		lastUpdateTime: time.Now(),
	}
}

func (c *Cache) Get(domain string) ([]string, bool) {
	if value, isLoad := c.dns.Load(domain); isLoad {
		//log.Println(domain + " match success")
		return value.([]string), true
	}
	return nil, false
}

func (c *Cache) Add(domain string, ip []string) {
	if c.number > 1500 {
		tmp := 0
		c.dns.Range(func(key, value interface{}) bool {
			c.dns.Delete(key)
			if tmp >= 80 {
				return false
			}
			return true
		})
		c.number -= 80

		if time.Since(c.lastUpdateTime) >= time.Hour {
			number := 0
			c.dns.Range(func(key, value interface{}) bool {
				number++
				return true
			})
			c.number = number
		}
	}
	c.dns.Store(domain, ip)
	c.number++
	//log.Println(domain+" Add success,number", c.number)
}
