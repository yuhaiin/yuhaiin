// Package badger provides a cache implementation using badger
package badger

import (
	"bytes"
	"errors"
	"iter"

	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/dgraph-io/badger/v4"
)

var (
	MigateKey             = []byte("MIGRATE_VERSION")
	_         cache.Cache = (*Cache)(nil)
)

type Cache struct {
	db     *badger.DB
	prefix []byte
}

func New(path string) (*Cache, error) {
	opts := badger.DefaultOptions(path).
		WithValueLogFileSize(8 << 20). // 8MB
		WithValueLogMaxEntries(10000).
		WithNumCompactors(4).
		WithNumLevelZeroTables(2).
		WithNumLevelZeroTablesStall(4).
		WithMaxLevels(4).
		WithMemTableSize(8 << 20)
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

func (c *Cache) Close() error {
	return c.db.Close()
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

func (c *Cache) Put(es iter.Seq2[[]byte, []byte]) error {
	wb := c.db.NewWriteBatch()
	defer wb.Cancel()

	for k, v := range es {
		if v == nil {
			continue
		}
		if err := wb.Set(c.makeKey(k), v); err != nil {
			return err
		}
	}

	return wb.Flush()
}

func (c *Cache) Delete(es iter.Seq[[]byte]) error {
	wb := c.db.NewWriteBatch()
	defer wb.Cancel()

	for k := range es {
		if err := wb.Delete(c.makeKey(k)); err != nil {
			return err
		}
	}

	return wb.Flush()
}

var errBreak = errors.New("break")

func (c *Cache) Range(f func(key []byte, value []byte) bool) error {
	err := c.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Seek(c.prefix); it.ValidForPrefix(c.prefix); it.Next() {
			item := it.Item()
			key := item.Key()
			err := item.Value(func(val []byte) error {
				if !f(bytes.TrimPrefix(key, c.prefix), val) {
					return errBreak
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	if errors.Is(err, errBreak) {
		return nil
	}

	return err
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

func (c *Cache) makeKey(k []byte) []byte {
	return append(c.prefix, k...)
}
