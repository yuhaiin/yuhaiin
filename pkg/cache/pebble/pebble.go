// Package pebble provides a cache implementation using pebble
package pebble

import (
	"bytes"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/cockroachdb/pebble"
)

var _ cache.Cache = (*Cache)(nil)

type Cache struct {
	db     *pebble.DB
	prefix []byte
	dir    string
}

func New(path string) (*Cache, error) {
	opts := &pebble.Options{
		MemTableSize: 2 << 20,
		DisableWAL:   true,
	}
	db, err := pebble.Open(path, opts)
	if err != nil {
		return nil, err
	}
	return &Cache{db: db, dir: path}, nil
}

func (c *Cache) Pebble() *pebble.DB {
	return c.db
}

func (c *Cache) Dir() string {
	return c.dir
}

func (c *Cache) Clear() error {
	start := []byte{0x00}
	end := []byte{0xff, 0xff, 0xff, 0xff}

	return c.db.DeleteRange(start, end, nil)
}

func (c *Cache) Get(k []byte) (v []byte, err error) {
	key := c.makeKey(k)
	v, closer, err := c.db.Get(key)
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()
	return bytes.Clone(v), nil
}

func (c *Cache) Put(k []byte, v []byte, opts ...func(*cache.PutOptions)) error {
	// pebble does not support TTL on entries
	return c.db.Set(c.makeKey(k), v, pebble.NoSync)
}

func (c *Cache) Delete(es []byte) error {
	return c.db.Delete(c.makeKey(es), pebble.NoSync)
}

func (c *Cache) Range(f func(key []byte, value []byte) bool) error {
	it, err := c.db.NewIter(&pebble.IterOptions{
		LowerBound: c.prefix,
		UpperBound: c.getUpperBound(),
	})
	if err != nil {
		return err
	}
	defer it.Close()

	for it.First(); it.Valid(); it.Next() {
		if !f(bytes.TrimPrefix(it.Key(), c.prefix), bytes.Clone(it.Value())) {
			break
		}
	}
	return nil
}

func (c *Cache) NewCache(str ...string) cache.Cache {
	if len(str) == 0 {
		return c
	}

	return &Cache{
		db:     c.db,
		prefix: c.cachePrefix(str...),
	}
}

func (c *Cache) CacheExists(str ...string) bool {
	if len(str) == 0 {
		return true
	}

	prefixToCheck := c.cachePrefix(str...)
	it, err := c.db.NewIter(&pebble.IterOptions{
		LowerBound: prefixToCheck,
		UpperBound: c.getUpperBoundPrefix(prefixToCheck),
	})
	if err != nil {
		return false
	}
	defer it.Close()

	return it.First()
}

func (c *Cache) DeleteBucket(str ...string) error {
	if len(str) == 0 {
		return nil
	}

	prefixToDelete := c.cachePrefix(str...)
	return c.db.DeleteRange(prefixToDelete, c.getUpperBoundPrefix(prefixToDelete), pebble.NoSync)
}

func (c *Cache) Batch(f func(txn cache.Batch) error) error {
	b := c.db.NewIndexedBatch()
	defer b.Close()
	batch := &Batch{
		b: b,
		c: c,
	}
	err := f(batch)
	if err != nil {
		return err
	}

	return b.Commit(pebble.NoSync)
}

func (c *Cache) Close() error {
	if err := c.db.Flush(); err != nil {
		return err
	}
	return c.db.Close()
}

func (c *Cache) makeKey(k []byte) []byte {
	key := make([]byte, len(c.prefix)+len(k))
	copy(key, c.prefix)
	copy(key[len(c.prefix):], k)
	return key
}

func (c *Cache) cacheKey(valueKey []byte, str ...string) []byte {
	prefix := c.cachePrefix(str...)
	key := make([]byte, len(prefix)+len(valueKey))
	copy(key, prefix)
	copy(key[len(prefix):], valueKey)
	return key
}

func (c *Cache) cachePrefix(str ...string) []byte {
	totalLen := len(c.prefix)
	for _, s := range str {
		totalLen += len(s) + 1 // +1 for '/'
	}

	newPrefix := make([]byte, totalLen)
	off := copy(newPrefix, c.prefix)

	for _, s := range str {
		copy(newPrefix[off:], s) // copy string bytes
		off += len(s)
		newPrefix[off] = '/' // separator
		off++
	}

	return newPrefix
}

func (c *Cache) getUpperBound() []byte {
	return c.getUpperBoundPrefix(c.prefix)
}

func (c *Cache) getUpperBoundPrefix(prefix []byte) []byte {
	if len(prefix) == 0 {
		return nil
	}
	end := make([]byte, len(prefix))
	copy(end, prefix)
	for i := len(end) - 1; i >= 0; i-- {
		end[i]++
		if end[i] != 0 {
			return end[:i+1]
		}
	}
	return nil // overflow, basically no upper bound
}

type Batch struct {
	b *pebble.Batch
	c *Cache
}

func (b *Batch) Put(k []byte, v []byte, opts ...func(*cache.PutOptions)) error {
	return b.b.Set(b.c.makeKey(k), v, nil)
}

func (b *Batch) Delete(k []byte) error {
	return b.b.Delete(b.c.makeKey(k), nil)
}

func (b *Batch) Get(k []byte) ([]byte, error) {
	v, closer, err := b.b.Get(b.c.makeKey(k))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()
	return bytes.Clone(v), nil
}

func (b *Batch) PutToCache(subCache []string, k []byte, v []byte, opts ...func(*cache.PutOptions)) error {
	key := b.c.cacheKey(k, subCache...)
	return b.b.Set(key, v, nil)
}

func (b *Batch) GetFromCache(subCache []string, k []byte) ([]byte, error) {
	key := b.c.cacheKey(k, subCache...)
	v, closer, err := b.b.Get(key)
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()
	return bytes.Clone(v), nil
}
