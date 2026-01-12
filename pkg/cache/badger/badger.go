// Package badger provides a cache implementation using badger
package badger

import (
	"bytes"
	"io"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
)

var (
	MigrateKey             = []byte("MIGRATE_VERSION")
	_          cache.Cache = (*Cache)(nil)
)

type Cache struct {
	db     *badger.DB
	prefix []byte
}

func New(path string) (*Cache, error) {
	opts := badger.DefaultOptions(path).
		WithValueLogFileSize(4 << 20). // 8MB
		WithValueLogMaxEntries(10000).
		WithNumCompactors(4).
		WithNumLevelZeroTables(2).
		WithNumLevelZeroTablesStall(4).
		WithNumVersionsToKeep(1).
		WithMaxLevels(4).
		WithMemTableSize(2 << 20).     // 2mb
		WithBaseTableSize(2 << 20).    // 2mb
		WithValueThreshold(256 << 10). // 256KB
		WithIndexCacheSize(1 << 20).
		WithNumMemtables(1).
		WithCompression(options.None).
		WithBlockCacheSize(0). // we don't use compression, so we don't need block cache
		WithSyncWrites(false).
		WithMetricsEnabled(true).
		WithCompactL0OnClose(true)
	if path == "" {
		opts = opts.WithInMemory(true)
	}
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &Cache{db: db}, nil
}

func (c *Cache) Badger() *badger.DB {
	return c.db
}

func (c *Cache) Get(k []byte) (v []byte, err error) {
	key := c.makeKey(k)
	err = c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		v, err = item.ValueCopy(nil)
		return err
	})
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	return
}

func (c *Cache) Put(k []byte, v []byte, opts ...func(*cache.PutOptions)) error {
	opt := cache.GetPutOptions(opts...)
	return c.db.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry(c.makeKey(k), v)
		if opt.TTL > 0 {
			entry.WithTTL(opt.TTL)
		}
		return txn.SetEntry(entry)
	})
}

func (c *Cache) Delete(es []byte) error {
	return c.db.Update(func(txn *badger.Txn) error {
		if err := txn.Delete(c.makeKey(es)); err != nil {
			return err
		}
		return nil
	})
}

func (c *Cache) Range(f func(key []byte, value []byte) bool) error {
	return c.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Seek(c.prefix); it.ValidForPrefix(c.prefix); it.Next() {
			item := it.Item()
			key := item.Key()
			err := item.Value(func(val []byte) error {
				if !f(bytes.TrimPrefix(key, c.prefix), val) {
					return io.EOF
				}
				return nil
			})
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
		return nil
	})
}

func (c *Cache) CachePrefix(str ...string) []byte {
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

func (c *Cache) cacheKey(valueKey []byte, str ...string) []byte {
	prefix := c.CachePrefix(str...)
	key := make([]byte, len(prefix)+len(valueKey))
	copy(key, prefix)
	copy(key[len(prefix):], valueKey)
	return key
}

func (c *Cache) NewCache(str ...string) cache.Cache {
	if len(str) == 0 {
		return c
	}

	return &Cache{
		db:     c.db,
		prefix: c.CachePrefix(str...),
	}
}

func (c *Cache) CacheExists(str ...string) bool {
	if len(str) == 0 {
		return true
	}

	var exists bool
	err := c.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.AllVersions = false
		it := txn.NewIterator(opts)
		defer it.Close()

		prefixToCheck := c.CachePrefix(str...)
		it.Seek(prefixToCheck)
		exists = it.ValidForPrefix(prefixToCheck)
		return nil
	})
	if err != nil {
		log.Info("CacheExists failed", "err", err)
	}

	return exists
}

func (c *Cache) DeleteBucket(str ...string) error {
	if len(str) == 0 {
		return nil
	}

	prefixToDelete := c.CachePrefix(str...)
	return c.db.DropPrefix(prefixToDelete)
}

func (c *Cache) Batch(f func(txn cache.Batch) error) error {
	return c.db.Update(func(txn *badger.Txn) error {
		b := &Batch{txn: txn, c: c}
		return f(b)
	})
}

func (c *Cache) makeKey(k []byte) []byte {
	key := make([]byte, len(c.prefix)+len(k))
	copy(key, c.prefix)
	copy(key[len(c.prefix):], k)
	return key
}

func (c *Cache) Clear() error {
	return c.db.DropAll()
}

func (c *Cache) Close() error {
	return c.db.Close()
}

func (c *Cache) Dir() string {
	return c.db.Opts().Dir
}

type Batch struct {
	txn *badger.Txn
	c   *Cache
}

func (b *Batch) Put(k []byte, v []byte, opts ...func(*cache.PutOptions)) error {
	opt := cache.GetPutOptions(opts...)
	entry := badger.NewEntry(b.c.makeKey(k), v)
	if opt.TTL > 0 {
		entry.WithTTL(opt.TTL)
	}

	return b.txn.SetEntry(entry)
}

func (b *Batch) Commit() error {
	return b.txn.Commit()
}

func (b *Batch) PutToCache(subCache []string, k []byte, v []byte, opts ...func(*cache.PutOptions)) error {
	key := b.c.cacheKey(k, subCache...)

	opt := cache.GetPutOptions(opts...)
	entry := badger.NewEntry(key, v)
	if opt.TTL > 0 {
		entry.WithTTL(opt.TTL)
	}

	return b.txn.SetEntry(entry)
}

func (b *Batch) Delete(k []byte) error {
	return b.txn.Delete(b.c.makeKey(k))
}

func (b *Batch) Get(k []byte) ([]byte, error) {
	item, err := b.txn.Get(b.c.makeKey(k))
	if err != nil {
		return nil, err
	}
	return item.ValueCopy(nil)
}

func (b *Batch) GetFromCache(subCache []string, k []byte) ([]byte, error) {
	key := b.c.cacheKey(k, subCache...)

	item, err := b.txn.Get(key)
	if err != nil {
		return nil, err
	}
	return item.ValueCopy(nil)
}
