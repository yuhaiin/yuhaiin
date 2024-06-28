package bbolt

import (
	"context"
	"errors"
	"sync"

	"go.etcd.io/bbolt"
)

type Type byte

const (
	Delete Type = iota
	Put
)

type NoSynncEntry struct {
	Keys  [][]byte
	Value []byte
	Type  Type
}

type Nosync struct {
	closed context.Context
	db     *bbolt.DB

	cache chan NoSynncEntry
	close context.CancelFunc

	bucketName []byte

	wg sync.WaitGroup
}

// NewNosyncCache It is not realtime cache, put is not blocking, get value maybe nil
func NewNosyncCache(db *bbolt.DB, bucketName string) *Nosync {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Nosync{
		db:         db,
		bucketName: []byte(bucketName),
		cache:      make(chan NoSynncEntry, 150),
		close:      cancel,
		closed:     ctx,
	}

	if db == nil {
		return c
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			select {
			case <-c.closed.Done():
				return
			case x := <-c.cache:
				switch x.Type {
				case Delete:
					c.delete(x.Keys...)
				case Put:
					c.put(x.Keys[0], x.Value)
				}
			}
		}
	}()

	return c
}

func (c *Nosync) Get(k []byte) (v []byte) {
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

func (c *Nosync) bucket(tx *bbolt.Tx) (*bbolt.Bucket, error) {
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

func (c *Nosync) Put(k, v []byte) {
	if c.db == nil {
		return
	}

	select {
	case <-c.closed.Done():
		return
	case c.cache <- NoSynncEntry{
		Type:  Put,
		Keys:  [][]byte{k},
		Value: v,
	}:
	}
}

func (c *Nosync) Delete(k ...[]byte) {
	if c.db == nil {
		return
	}

	select {
	case <-c.closed.Done():
		return
	case c.cache <- NoSynncEntry{
		Type: Delete,
		Keys: k,
	}:
	}
}

func (c *Nosync) Range(f func(key []byte, value []byte) bool) {
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

func (c *Nosync) Close() error {
	c.close()
	if c.db == nil {
		return nil
	}
	c.wg.Wait()
	return nil
}

func (c *Nosync) put(k, v []byte) {
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

func (c *Nosync) delete(k ...[]byte) {
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
