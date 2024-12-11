package yuhaiin

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/kv"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	cb "github.com/Asutorufa/yuhaiin/pkg/utils/cache/bbolt"
	"go.etcd.io/bbolt"
)

var dbPath string
var socketPath string
var db cache.Cache
var kvServer io.Closer
var mu sync.Mutex

func InitDB(path string, sp string) error {
	dbPath = filepath.Join(path, "yuhaiin.db")
	socketPath = filepath.Join(sp, "kv.sock")
	return nil
}

func initKVStore() cache.Cache {
	if db != nil {
		return db
	}

	mu.Lock()
	defer mu.Unlock()

	if db != nil {
		return db
	}

	var err error
	db, err = DoubleDial()
	if err != nil {
		panic(fmt.Errorf("double dial failed: %w", err))
	}

	return db
}

type androidDB struct {
	batch []string
	store cache.Cache

	mu sync.Mutex
}

func newAndroidDB() *androidDB {
	s := initKVStore()
	return &androidDB{
		store: s,
	}
}

func (a *androidDB) resetStore() {
	mu.Lock()
	db.Close()
	db = nil
	mu.Unlock()

	s := initKVStore()

	for _, v := range a.batch {
		s = s.NewCache(v)
	}

	a.mu.Lock()
	a.store = s
	a.mu.Unlock()
}

func (a *androidDB) Put(k []byte, v []byte) error {
	err := a.store.Put(k, v)
	if err != nil {
		a.resetStore()
		return a.store.Put(k, v)
	}

	return nil
}

func (a *androidDB) Get(k []byte) ([]byte, error) {
	b, err := a.store.Get(k)
	if err != nil {
		a.resetStore()
		b, err = a.store.Get(k)
	}
	return b, err
}

func (a *androidDB) Delete(k ...[]byte) error {
	err := a.store.Delete(k...)
	if err != nil {
		a.resetStore()
		return a.store.Delete(k...)
	}
	return nil
}

func (a *androidDB) Range(f func(key []byte, value []byte) bool) error {
	err := a.store.Range(f)
	if err != nil {
		a.resetStore()
		return a.store.Range(f)
	}
	return nil
}

func (a *androidDB) Close() error {
	return a.store.Close()
}

func (a *androidDB) NewCache(b string) cache.Cache {
	return &androidDB{
		batch: append(a.batch, b),
		store: a.store.NewCache(b),
	}
}

func DoubleDial() (cache.Cache, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type chStore struct {
		store cache.Cache
		err   error
	}
	ch := make(chan chStore)

	sendData := func(s cache.Cache, err error) {
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
		log.Info("init global db", "path", dbPath)

		if err := os.MkdirAll(filepath.Dir(dbPath), os.ModePerm); err != nil {
			sendData(nil, fmt.Errorf("mkdir failed: %w", err))
			return
		}

		odb, err := bbolt.Open(dbPath, os.ModePerm, &bbolt.Options{Timeout: time.Second * 2})
		if err != nil {
			sendData(nil, err)
			return
		}

		cb := cb.NewCache(odb, "yuhaiin")

		_ = os.Remove(socketPath)

		s, err := kv.Start(socketPath, cb)
		if err != nil {
			log.Error("start kv server failed", slog.Any("err", err))
		} else {
			kvServer = s
		}

		sendData(cb, err)
	}()

	go func() { sendData(kv.NewClient(socketPath)) }()

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
		return s.store, nil
	}
}

type Store interface {
	PutString(key string, value string)
	PutInt(key string, value int32)
	PutBoolean(key string, value bool)
	PutLong(key string, value int64)
	PutFloat(key string, value float32)
	GetString(key string) string
	GetInt(key string) int32
	GetBoolean(key string) bool
	GetLong(key string) int64
	GetFloat(key string) float32
}

type storeImpl struct {
	batch string
	db    cache.Cache
	mu    sync.RWMutex
}

func (s *storeImpl) initDB() {
	s.mu.RLock()
	if s.db != nil {
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return
	}

	s.db = newAndroidDB().NewCache(s.batch)
}

func (s *storeImpl) PutString(key string, value string) {
	s.initDB()
	_ = s.db.Put([]byte(key), []byte(value))
}

func (s *storeImpl) PutInt(key string, value int32) {
	s.initDB()
	bytes := binary.NativeEndian.AppendUint32(nil, uint32(value))
	_ = s.db.Put([]byte(key), bytes)
}

func (s *storeImpl) PutBoolean(key string, value bool) {
	s.initDB()
	_ = s.db.Put([]byte(key), ifOr(value, []byte{1}, []byte{0}))
}

func (s *storeImpl) PutLong(key string, value int64) {
	s.initDB()
	bytes := binary.NativeEndian.AppendUint64(nil, uint64(value))
	_ = s.db.Put([]byte(key), bytes)
}

func (s *storeImpl) PutFloat(key string, value float32) {
	s.initDB()
	bytes := binary.NativeEndian.AppendUint32(nil, math.Float32bits(value))
	_ = s.db.Put([]byte(key), bytes)
}

func (s *storeImpl) GetString(key string) string {
	s.initDB()
	bytes, _ := s.db.Get([]byte(key))
	if bytes == nil {
		return defaultStringValue[key]
	}
	return string(bytes)
}

func (s *storeImpl) GetInt(key string) int32 {
	s.initDB()
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) < 4 || bytes == nil {
		return defaultIntValue[key]
	}

	value := binary.NativeEndian.Uint32(bytes)
	return int32(value)
}

func (s *storeImpl) GetBoolean(key string) bool {
	s.initDB()
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) == 0 || bytes == nil {
		return defaultBoolValue[key] == 1
	}

	return bytes[0] == 1
}

func (s *storeImpl) GetLong(key string) int64 {
	s.initDB()
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) < 8 || bytes == nil {
		return defaultLangValue[key]
	}

	value := binary.NativeEndian.Uint64(bytes)

	return int64(value)
}

func (s *storeImpl) GetFloat(key string) float32 {
	s.initDB()
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) < 4 || bytes == nil {
		return defaultFloatValue[key]
	}
	return math.Float32frombits(binary.NativeEndian.Uint32(bytes))
}

func GetStore(prefix string) Store {
	return &storeImpl{batch: prefix}
}

func CloseStore() {
	mu.Lock()
	defer mu.Unlock()

	if db != nil {
		db.Close()
		db = nil
	}

	if kvServer != nil {
		kvServer.Close()
		kvServer = nil
	}
}
