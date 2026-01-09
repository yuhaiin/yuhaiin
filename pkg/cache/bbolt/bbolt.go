package bbolt

import (
	"errors"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"go.etcd.io/bbolt"
)

type bucketer interface {
	Bucket(name []byte) *bbolt.Bucket
	DeleteBucket(name []byte) error
	CreateBucketIfNotExists(name []byte) (*bbolt.Bucket, error)
}

type Cache struct {
	db *bbolt.DB

	bucketName [][]byte
}

func NewCache(db *bbolt.DB, bucketName ...string) *Cache {
	c := &Cache{db: db}

	for _, name := range bucketName {
		c.bucketName = append(c.bucketName, []byte(name))
	}

	return c
}

func (c *Cache) Get(k []byte) (v []byte, err error) {
	if c.db == nil {
		return nil, nil
	}

	err = c.db.View(func(tx *bbolt.Tx) error {
		bk, err := c.bucket(tx, true)
		if err != nil {
			return nil
		}

		vv := bk.Get(k)
		if vv != nil {
			v = make([]byte, len(vv))
			copy(v, vv)
		}
		return nil
	})

	return v, err
}

func (c *Cache) bucket(tx *bbolt.Tx, readOnly bool) (*bbolt.Bucket, error) {
	if len(c.bucketName) == 0 {
		return nil, fmt.Errorf("bucket name is empty")
	}

	var (
		next bucketer = tx
		err  error
	)

	for _, v := range c.bucketName {
		x := next.Bucket(v)
		if x == nil {
			if readOnly {
				return nil, cache.ErrBucketNotExist
			}

			x, err = next.CreateBucketIfNotExists(v)
			if err != nil {
				return nil, err
			}
		}

		next = x
	}

	return next.(*bbolt.Bucket), nil
}

func (c *Cache) Put(k []byte, v []byte, opts ...func(*cache.PutOptions)) error {
	if c.db == nil {
		return nil
	}

	return c.db.Batch(func(tx *bbolt.Tx) error {
		bk, err := c.bucket(tx, false)
		if err != nil {
			return err
		}

		if err := bk.Put(k, v); err != nil {
			return err
		}
		return nil
	})
}

func (c *Cache) Delete(k []byte) error {
	if c.db == nil {
		return nil
	}

	return c.db.Batch(func(tx *bbolt.Tx) error {
		bk, err := c.bucket(tx, true)
		if err != nil {
			return nil
		}

		if k == nil {
			return nil
		}

		if err := bk.Delete(k); err != nil {
			return err
		}

		return nil
	})
}

func (c *Cache) Range(f func(key []byte, value []byte) bool) error {
	if c.db == nil {
		return nil
	}

	return c.db.View(func(tx *bbolt.Tx) error {
		bkt, err := c.bucket(tx, true)
		if err != nil {
			return err
		}

		return bkt.ForEach(func(k, v []byte) error {
			if !f(k, v) {
				return errors.New("break")
			}
			return nil
		})
	})
}

func (c *Cache) NewCache(str ...string) cache.Cache {
	if len(str) == 0 {
		return c
	}

	bucketName := make([][]byte, 0, len(str)+len(c.bucketName))
	bucketName = append(bucketName, c.bucketName...)
	for _, v := range str {
		bucketName = append(bucketName, []byte(v))
	}

	return &Cache{
		db:         c.db,
		bucketName: bucketName,
	}
}

func (c *Cache) Batch(f func(txn cache.Batch) error) error {
	return c.db.Batch(func(tx *bbolt.Tx) error {
		txn, err := c.bucket(tx, false)
		if err != nil {
			return err
		}
		return f(&batch{txn: txn})
	})
}

func (c *Cache) DeleteBucket(str ...string) error {
	if len(str) == 0 {
		return nil
	}

	bucketName := make([][]byte, 0, len(str)+len(c.bucketName))
	bucketName = append(bucketName, c.bucketName...)
	for _, v := range str {
		bucketName = append(bucketName, []byte(v))
	}

	return c.db.Update(func(tx *bbolt.Tx) error {
		var next bucketer = tx

		for _, v := range bucketName[:len(bucketName)-1] {
			bt := next.Bucket(v)
			if bt == nil {
				return nil
			}

			next = bt
		}

		return next.DeleteBucket(bucketName[len(bucketName)-1])
	})
}

type batch struct {
	txn *bbolt.Bucket
}

func (b *batch) Put(k []byte, v []byte, opts ...func(*cache.PutOptions)) error {
	return b.txn.Put(k, v)
}

func (b *batch) Delete(k []byte) error {
	return b.txn.Delete(k)
}

func (b *batch) Get(k []byte) ([]byte, error) {
	return b.txn.Get(k), nil
}
