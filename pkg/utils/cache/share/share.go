package share

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	cb "github.com/Asutorufa/yuhaiin/pkg/utils/cache/bbolt"
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
	store  *Entry
	dbPath string
	socket string
	mu     sync.Mutex
}

func NewShareCache(dbPath string, socket string) *ShareDB {
	s := &ShareDB{
		dbPath: dbPath,
		socket: socket,
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

func (s *ShareDB) openBboltDB() (*Entry, error) {
	if err := os.MkdirAll(filepath.Dir(s.dbPath), os.ModePerm); err != nil {
		return nil, err
	}

	odb, err := bbolt.Open(s.dbPath, os.ModePerm, &bbolt.Options{
		Timeout:        time.Second * 2,
		Logger:         cb.BBoltDBLogger{},
		NoFreelistSync: true,
	})
	if err != nil {
		return nil, err
	}

	// set big batch delay to reduce sync for fake dns and connection cache
	odb.MaxBatchDelay = time.Millisecond * 300

	cb := cb.NewCache(odb, "yuhaiin")

	_ = os.Remove(s.socket)

	ss, err := NewServer(s.socket, cb)
	if err != nil {
		_ = odb.Close()
		return nil, err
	}

	return &Entry{
		closer: func() error {
			_ = ss.Close()
			return odb.Close()
		},
		cache: cb,
		path:  s.dbPath,
	}, nil
}

func (s *ShareDB) openHTTPDB() (*Entry, error) {
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
		s.openBboltDB,
		s.openHTTPDB,
	} {
		go func() {
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
		}()
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
	batch []string
	db    *ShareDB
}

func NewCache(db *ShareDB, batch ...string) *Cache {
	return &Cache{
		batch: batch,
		db:    db,
	}
}

func (a *Cache) Put(k iter.Seq2[[]byte, []byte]) error {
	return a.db.do(a.batch, func(s cache.Cache) error { return s.Put(k) })
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

func (a *Cache) Delete(k ...[]byte) error {
	return a.db.do(a.batch, func(s cache.Cache) error { return s.Delete(k...) })
}

func (a *Cache) Range(f func(key []byte, value []byte) bool) error {
	return a.db.do(a.batch, func(c cache.Cache) error { return c.Range(f) })
}

func (a *Cache) NewCache(str ...string) cache.Cache {
	return NewCache(a.db, append(a.batch, str...)...)
}
