package bbolt

import (
	"errors"
	"fmt"
	"iter"

	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"go.etcd.io/bbolt"
)

type bucketer interface {
	Bucket(name []byte) *bbolt.Bucket
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

func (c *Cache) Put(es iter.Seq2[[]byte, []byte]) error {
	if c.db == nil {
		return nil
	}

	return c.db.Batch(func(tx *bbolt.Tx) error {
		bk, err := c.bucket(tx, false)
		if err != nil {
			return err
		}

		for k, v := range es {
			if err := bk.Put(k, v); err != nil {
				return err
			}
		}
		return nil
	})
}

func (c *Cache) Delete(k ...[]byte) error {
	if c.db == nil {
		return nil
	}

	return c.db.Batch(func(tx *bbolt.Tx) error {
		bk, err := c.bucket(tx, true)
		if err != nil {
			return nil
		}

		for _, kk := range k {
			if kk == nil {
				continue
			}

			if err := bk.Delete(kk); err != nil {
				return err
			}
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

	bucket := c.bucketName
	for _, v := range str {
		bucket = append(bucket, []byte(v))
	}

	return &Cache{
		db:         c.db,
		bucketName: append(c.bucketName, bucket...),
	}
}
