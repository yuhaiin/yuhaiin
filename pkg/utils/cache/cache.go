package cache

import "go.etcd.io/bbolt"

type Cache struct {
	db *bbolt.DB

	bucketName []byte
}

func NewCache(db *bbolt.DB, bucketName string) *Cache {
	return &Cache{
		db:         db,
		bucketName: []byte(bucketName),
	}
}

func (c *Cache) Get(k []byte) (v []byte) {
	if c.db == nil {
		return nil
	}

	c.db.View(func(tx *bbolt.Tx) error {
		bk := tx.Bucket(c.bucketName)
		if bk == nil {
			return nil
		}

		v = bk.Get(k)

		return nil
	})

	return v
}

func (c *Cache) Put(k, v []byte) {
	if c.db == nil {
		return
	}

	c.db.Batch(func(tx *bbolt.Tx) error {
		bk, err := tx.CreateBucketIfNotExists(c.bucketName)
		if err != nil {
			return err
		}

		bk.Put(k, v)
		return nil
	})
}

func (c *Cache) Delete(k ...[]byte) {
	if c.db == nil {
		return
	}
	c.db.Batch(func(tx *bbolt.Tx) error {
		b := tx.Bucket(c.bucketName)
		if b == nil {
			return nil
		}

		for _, kk := range k {
			if kk == nil {
				continue
			}

			b.Delete(kk)
		}

		return nil
	})
}
