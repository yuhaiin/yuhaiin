package bbolt

import (
	"errors"

	"go.etcd.io/bbolt"
)

type Cache struct {
	db *bbolt.DB

	bucketName []byte
}

func NewCache(db *bbolt.DB, bucketName string) *Cache {
	c := &Cache{
		db:         db,
		bucketName: []byte(bucketName),
	}

	return c
}

func (c *Cache) Get(k []byte) (v []byte) {
	if c.db == nil {
		return nil
	}

	_ = c.db.View(func(tx *bbolt.Tx) error {
		bk := tx.Bucket(c.bucketName)
		if bk == nil {
			return nil
		}

		vv := bk.Get(k)
		if vv != nil {
			v = make([]byte, len(vv))
			copy(v, vv)
		}
		return nil
	})

	return v
}

func (c *Cache) bucket(tx *bbolt.Tx) (*bbolt.Bucket, error) {
	bk := tx.Bucket(c.bucketName)
	if bk == nil {
		var err error
		bk, err = tx.CreateBucketIfNotExists(c.bucketName)
		if err != nil {
			return nil, err
		}
	}

	return bk, nil
}

func (c *Cache) Put(k, v []byte) {
	if c.db == nil {
		return
	}

	_ = c.db.Batch(func(tx *bbolt.Tx) error {
		bk, err := c.bucket(tx)
		if err != nil {
			return err
		}
		return bk.Put(k, v)
	})
}

func (c *Cache) Delete(k ...[]byte) {
	if c.db == nil {
		return
	}

	_ = c.db.Batch(func(tx *bbolt.Tx) error {
		b := tx.Bucket(c.bucketName)

		for _, kk := range k {
			if kk == nil {
				continue
			}

			if b != nil {
				if err := b.Delete(kk); err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func (c *Cache) Range(f func(key []byte, value []byte) bool) {
	if c.db == nil {
		return
	}

	_ = c.db.View(func(tx *bbolt.Tx) error {
		bkt, err := c.bucket(tx)
		if err != nil {
			return err
		}

		_ = bkt.ForEach(func(k, v []byte) error {
			if !f(k, v) {
				return errors.New("break")
			}
			return nil
		})

		return nil
	})
}

func (c *Cache) Close() error {
	return nil
}
