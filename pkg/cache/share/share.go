package share

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/cache/badger"
	cb "github.com/Asutorufa/yuhaiin/pkg/cache/bbolt"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"go.etcd.io/bbolt"
)

type Entry struct {
	closer func() error
	cache  cache.Cache
	path   string

	buckets syncmap.SyncMap[string, cache.Cache]
}

func (e *Entry) Close() error {
	if e == nil || e.closer == nil {
		return nil
	}

	return e.closer()
}

func (e *Entry) GetBucketCache(bucket ...string) cache.Cache {
	cache, _, _ := e.buckets.LoadOrCreate(strings.Join(bucket, "-"), func() (cache.Cache, error) {
		return e.cache.NewCache(bucket...), nil
	})

	return cache
}

// ShareDB open local bbotdb or connect to unix socket grpc
type ShareDB struct {
	store        *Entry
	oldDBPath    string
	badgerDBPath string
	socket       string
	mu           sync.Mutex
}

func NewShareCache(oldDBPath, badgerDBPath string, socket string) *ShareDB {
	s := &ShareDB{
		oldDBPath:    oldDBPath,
		badgerDBPath: badgerDBPath,
		socket:       socket,
	}

	_, _, err := s.init()
	if err != nil {
		log.Warn("try init kv store failed", "err", err)
	}

	return s
}

func (a *ShareDB) init() (*Entry, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.store != nil {
		return a.store, false, nil
	}

	e, err := a.openStore()
	if err != nil {
		return nil, false, fmt.Errorf("open share store failed: %w", err)
	}

	a.store = e

	return a.store, true, nil
}

func (a *ShareDB) reset() (*Entry, error) {
	a.mu.Lock()
	if a.store != nil {
		_ = a.store.Close()
	}
	a.store = nil
	a.mu.Unlock()

	e, _, err := a.init()
	return e, err
}

func (a *ShareDB) do(bucket []string, f func(cache.Cache) error) error {
	store, inited, err := a.init()
	if err != nil {
		return err
	}

	err = f(store.GetBucketCache(bucket...))
	if err == nil {
		return nil
	}

	if inited {
		return err
	}

	store, err = a.reset()
	if err != nil {
		return err
	}

	return f(store.GetBucketCache(bucket...))
}

func (a *ShareDB) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.store != nil {
		return a.store.Close()
	}

	return nil
}

func (s *ShareDB) migrateDB(c *badger.Cache) error {
	v, err := c.Get(badger.MigrateKey)
	if err != nil {
		return err
	}

	ver := 1

	if len(v) != 0 && v[0] == byte(ver) {
		return nil
	}

	_, err = os.Stat(s.oldDBPath)
	if err == nil {
		odb, err := bbolt.Open(s.oldDBPath, os.ModePerm, &bbolt.Options{
			Timeout: time.Second * 2,
			Logger:  cb.BBoltDBLogger{},
		})
		if err == nil {
			// new user the old will not exist, so just skip here
			defer odb.Close()

			err = c.NewCache("yuhaiin", "Default").Batch(func(txn cache.Batch) error {
				var err error
				cb.NewCache(odb, "yuhaiin", "Default").Range(func(key, value []byte) bool {
					log.Info("migrate key", "key", string(key))
					err = txn.Put(append([]byte{}, key...), append([]byte{}, value...))
					return err == nil
				})
				return err
			})
			if err != nil {
				_ = odb.Close()
				return err
			}
		}
	}

	err = c.Put(badger.MigrateKey, []byte{byte(ver)})
	if err != nil {
		return err
	}

	log.Info("migrate old db success")
	return nil
}

func (s *ShareDB) openLocal() (*Entry, error) {
	c, err := badger.New(s.badgerDBPath)
	if err != nil {
		return nil, err
	}

	if err := s.migrateDB(c); err != nil {
		_ = c.Badger().Close()
		return nil, err
	}

	cb := c.NewCache("yuhaiin")

	_ = os.Remove(s.socket)

	ss, err := NewServer(s.socket, cb)
	if err != nil {
		_ = c.Badger().Close()
		return nil, err
	}

	return &Entry{
		closer: func() error {
			_ = ss.Close()
			return c.Badger().Close()
		},
		cache: cb,
		path:  s.badgerDBPath,
	}, nil
}

func (s *ShareDB) openRemote() (*Entry, error) {
	hkv := NewClient(s.socket)

	if err := hkv.Ping(); err != nil {
		return nil, err
	}

	return &Entry{
		cache: hkv,
		path:  s.socket,
	}, nil
}

// openStore open local db or try to connect remote db
func (s *ShareDB) openStore() (*Entry, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan *Entry)
	errCh := make(chan error)

	for _, open := range []func() (*Entry, error){
		s.openLocal,
		s.openRemote,
	} {
		go func(open func() (*Entry, error)) {
			e, err := open()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				case errCh <- err:
				}
			} else {
				select {
				case <-ctx.Done():
					_ = e.Close()
					return
				case ch <- e:
				}
			}
		}(open)
	}

	var er error
	for range 2 {
		select {
		case <-ctx.Done():
			return nil, errors.Join(er, ctx.Err())
		case err := <-errCh:
			er = errors.Join(er, err)
		case s := <-ch:
			log.Info("share bbolt db open success", "type", reflect.TypeOf(s.cache), "path", s.path)
			return s, nil
		}
	}

	return nil, er
}

var _ cache.Cache = (*Cache)(nil)

type Cache struct {
	db    *ShareDB
	batch []string
}

func NewCache(db *ShareDB, batch ...string) *Cache {
	return &Cache{
		batch: batch,
		db:    db,
	}
}

func (a *Cache) Put(k []byte, v []byte, opts ...func(*cache.PutOptions)) error {
    return a.db.do(a.batch, func(s cache.Cache) error { return s.Put(k, v, opts...) })
}

func (a *Cache) Get(k []byte) ([]byte, error) {
	var b []byte
	err := a.db.do(a.batch, func(s cache.Cache) error {
		var err error
		b, err = s.Get(k)
		return err
	})

	return b, err
}

func (a *Cache) Delete(k []byte) error {
	return a.db.do(a.batch, func(s cache.Cache) error { return s.Delete(k) })
}

func (a *Cache) Range(f func(key []byte, value []byte) bool) error {
	return a.db.do(a.batch, func(c cache.Cache) error { return c.Range(f) })
}

func (a *Cache) DeleteBucket(str ...string) error {
	return a.db.do(a.batch, func(c cache.Cache) error { return c.DeleteBucket(str...) })
}

func (a *Cache) NewCache(str ...string) cache.Cache {
	buckets := make([]string, 0, len(a.batch)+len(str))
	buckets = append(buckets, a.batch...)
	buckets = append(buckets, str...)
	return NewCache(a.db, buckets...)
}

func (a *Cache) Batch(f func(txn cache.Batch) error) error {
	return a.db.do(a.batch, func(c cache.Cache) error { return c.Batch(f) })
}
