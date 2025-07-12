package share

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/kv"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	cb "github.com/Asutorufa/yuhaiin/pkg/utils/cache/bbolt"
	"go.etcd.io/bbolt"
)

var _ cache.Cache = (*ShareCache)(nil)

// ShareCache open local bbotdb or connect to unix socket grpc
type ShareCache struct {
	store  cache.RecursionCache
	dbPath string
	socket string
	batch  []string
	mu     sync.Mutex
}

func NewShareCache(dbPath string, socket string, batch ...string) *ShareCache {
	return &ShareCache{
		dbPath: dbPath,
		socket: socket,
		batch:  batch,
	}
}

func (a *ShareCache) initKVStore() (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.store != nil {
		return false, nil
	}

	s, err := a.OpenStore()
	if err != nil {
		return false, fmt.Errorf("open share store failed: %w", err)
	}

	for _, v := range a.batch {
		s = s.NewCache(v)
	}

	a.store = s

	return true, nil
}

func (a *ShareCache) resetStore() error {
	a.mu.Lock()
	a.store.Close()
	a.store = nil
	a.mu.Unlock()

	_, err := a.initKVStore()
	return err
}

func (a *ShareCache) do(f func(cache.Cache) error) error {
	inited, err := a.initKVStore()
	if err != nil {
		return err
	}

	err = f(a.store)
	if err != nil {
		if !inited {
			err = a.resetStore()
			if err != nil {
				return err
			}

			return f(a.store)
		}

		return err
	}

	return nil
}

func (a *ShareCache) Put(k []byte, v []byte) error {
	return a.do(func(s cache.Cache) error { return s.Put(k, v) })
}

func (a *ShareCache) Get(k []byte) ([]byte, error) {
	var b []byte
	err := a.do(func(s cache.Cache) error {
		var err error
		b, err = s.Get(k)
		return err
	})

	return b, err
}

func (a *ShareCache) Delete(k ...[]byte) error {
	return a.do(func(s cache.Cache) error { return s.Delete(k...) })
}

func (a *ShareCache) Range(f func(key []byte, value []byte) bool) error {
	return a.do(func(c cache.Cache) error { return c.Range(f) })
}

func (a *ShareCache) Close() error {
	if a.store != nil {
		return a.store.Close()
	}

	return nil
}

type closeCache struct {
	cache.RecursionCache
	kvServer io.Closer
}

func (c *closeCache) Close() error {
	if c.kvServer != nil {
		_ = c.kvServer.Close()
	}
	return c.RecursionCache.Close()
}

func (c *closeCache) NewCache(b string) cache.RecursionCache {
	return &closeCache{
		RecursionCache: c.RecursionCache.NewCache(b),
		kvServer:       c.kvServer,
	}
}

// OpenStore open local db or try to connect remote db
func (s *ShareCache) OpenStore() (cache.RecursionCache, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type chStore struct {
		store cache.RecursionCache
		err   error
	}
	ch := make(chan chStore)

	sendData := func(s cache.RecursionCache, err error) {
		select {
		case <-ctx.Done():
			return
		case ch <- chStore{
			store: s,
			err:   err,
		}:
		}
	}

	remain := 2

	go func() {
		if err := os.MkdirAll(filepath.Dir(s.dbPath), os.ModePerm); err != nil {
			sendData(nil, fmt.Errorf("mkdir failed: %w", err))
			return
		}

		odb, err := bbolt.Open(s.dbPath, os.ModePerm, &bbolt.Options{
			Timeout: time.Second * 2,
			Logger:  cb.BBoltDBLogger{},
		})
		if err != nil {
			sendData(nil, err)
			return
		}

		// set big batch delay to reduce sync for fake dns and connection cache
		odb.MaxBatchDelay = time.Millisecond * 300

		cb := cb.NewCache(odb, "yuhaiin")

		_ = os.Remove(s.socket)

		s, err := kv.Start(s.socket, cb)
		if err != nil {
			log.Error("start kv server failed", slog.Any("err", err))
		}

		sendData(&closeCache{cb, s}, err)
	}()

	go func() { sendData(kv.NewClient(s.socket)) }()

	log.Info("start try to open share cache")

	var er error
	for {
		s := <-ch
		remain--
		if s.err != nil {
			er = errors.Join(er, s.err)
			if remain == 0 {
				return nil, er
			}
			continue
		}

		log.Info("share bbolt db open success", "type", reflect.TypeOf(s.store))

		return s.store, nil
	}
}
