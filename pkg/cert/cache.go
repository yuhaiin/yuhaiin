package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type cacheEntry struct {
	certificate *tls.Certificate
	used        uint64
}

// Cache belongs to one CA identity. Replacing the CA means replacing the cache.
// Expiring certificates are reissued; concurrent misses for a key are coalesced.
type Cache struct {
	ca       *Ca
	capacity int
	mu       sync.Mutex
	entries  map[string]cacheEntry
	clock    uint64
	flight   singleflight.Group
}

func NewCache(ca *Ca, capacity int) *Cache {
	return &Cache{ca: ca, capacity: max(capacity, 1), entries: make(map[string]cacheEntry)}
}
func (c *Cache) Len() int      { c.mu.Lock(); defer c.mu.Unlock(); return len(c.entries) }
func (c *Cache) Capacity() int { return c.capacity }
func (c *Cache) load(key string) *tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || entry.certificate.Leaf == nil || time.Until(entry.certificate.Leaf.NotAfter) < time.Hour {
		return nil
	}
	c.clock++
	entry.used = c.clock
	c.entries[key] = entry
	return entry.certificate
}
func (c *Cache) Get(algorithm x509.PublicKeyAlgorithm, hosts ...string) (*tls.Certificate, error) {
	if algorithm == x509.UnknownPublicKeyAlgorithm {
		algorithm = x509.ECDSA
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("certificate host is required")
	}
	for _, host := range hosts {
		if host == "" || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n/ ") {
			return nil, fmt.Errorf("invalid certificate host")
		}
	}
	key := fmt.Sprintf("%d:%s", algorithm, strings.Join(hosts, "\x00"))
	if certificate := c.load(key); certificate != nil {
		return certificate, nil
	}
	value, err, _ := c.flight.Do(key, func() (any, error) {
		if certificate := c.load(key); certificate != nil {
			return certificate, nil
		}
		if time.Until(c.ca.Cert.NotAfter) < time.Hour {
			return nil, fmt.Errorf("CA has expired or expires within one hour")
		}
		leaf, err := c.ca.GenerateServerCertWithAlgorithm(algorithm, hosts...)
		if err != nil {
			return nil, err
		}
		certificate, err := leaf.TlsCert()
		if err != nil {
			return nil, err
		}
		certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return nil, err
		}
		if len(c.ca.Cert.Raw) > 0 {
			certificate.Certificate = append(certificate.Certificate, c.ca.Cert.Raw)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if len(c.entries) >= c.capacity {
			var oldest string
			var used uint64
			for k, v := range c.entries {
				if oldest == "" || v.used < used {
					oldest, used = k, v.used
				}
			}
			delete(c.entries, oldest)
		}
		c.clock++
		c.entries[key] = cacheEntry{&certificate, c.clock}
		return &certificate, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(*tls.Certificate), nil
}
