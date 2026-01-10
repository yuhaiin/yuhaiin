// Package badger provides a cache implementation using badger
package badger

import (
	"bytes"
	"io"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
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

func (c *Cache) NewCache(str ...string) cache.Cache {
	if len(str) == 0 {
		return c
	}

	newPrefix := make([]byte, len(c.prefix), len(c.prefix)+len(str)*5)
	copy(newPrefix, c.prefix)

	for _, s := range str {
		newPrefix = append(newPrefix, []byte(s)...)
		newPrefix = append(newPrefix, '/') // separator
	}

	return &Cache{
		db:     c.db,
		prefix: newPrefix,
	}
}

func (c *Cache) CacheExists(str ...string) bool {
	if len(str) == 0 {
		return true
	}

	prefixToCheck := make([]byte, len(c.prefix), len(c.prefix)+len(str)*5)
	copy(prefixToCheck, c.prefix)

	for _, s := range str {
		prefixToCheck = append(prefixToCheck, []byte(s)...)
		prefixToCheck = append(prefixToCheck, '/') // separator
	}

	var exists bool
	_ = c.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		it.Seek(prefixToCheck)
		exists = it.ValidForPrefix(prefixToCheck)
		return nil
	})

	return exists
}

func (c *Cache) DeleteBucket(str ...string) error {
	if len(str) == 0 {
		return nil
	}

	prefixToDelete := make([]byte, len(c.prefix), len(c.prefix)+len(str)*5)
	copy(prefixToDelete, c.prefix)

	for _, s := range str {
		prefixToDelete = append(prefixToDelete, []byte(s)...)
		prefixToDelete = append(prefixToDelete, '/') // separator
	}

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
