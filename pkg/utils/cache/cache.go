package cache

import (
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type Cache interface {
	Get(k []byte) (v []byte, err error)
	Put(k, v []byte) error
	Delete(k ...[]byte) error
	Close() error
	Range(f func(key []byte, value []byte) bool) error
}

type RecursionCache interface {
	Cache
	NewCache(str string) RecursionCache
}

var _ RecursionCache = (*MockCache)(nil)

type MockCache struct {
	OnPut func(k, v []byte)
}

func (m *MockCache) Get(k []byte) (v []byte, _ error) { return nil, nil }
func (m *MockCache) Put(k, v []byte) error {
	if m.OnPut != nil {
		m.OnPut(k, v)
	}
	return nil
}
func (m *MockCache) Delete(k ...[]byte) error                          { return nil }
func (m *MockCache) Range(f func(key []byte, value []byte) bool) error { return nil }
func (m *MockCache) Close() error                                      { return nil }
func (m *MockCache) NewCache(str string) RecursionCache                { return &MockCache{} }
func NewMockCache() Cache                                              { return &MockCache{} }

var ErrBucketNotExist = errors.New("bucket not exist")

var _ RecursionCache = (*MemoryCache)(nil)

type MemoryCache struct {
	cache    syncmap.SyncMap[string, []byte]
	subStore syncmap.SyncMap[string, RecursionCache]
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{}
}

func (m *MemoryCache) Get(k []byte) (v []byte, err error) {
	x, _ := m.cache.Load(string(k))
	return x, nil
}

func (m *MemoryCache) Put(k, v []byte) error {
	m.cache.Store(string(k), v)
	return nil
}

func (m *MemoryCache) Delete(k ...[]byte) error {
	for _, k := range k {
		m.cache.Delete(string(k))
	}
	return nil
}

func (m *MemoryCache) Range(f func(key []byte, value []byte) bool) error {
	m.cache.Range(func(key string, value []byte) bool {
		return f([]byte(key), value)
	})
	return nil
}

func (m *MemoryCache) Close() error {
	return nil
}

func (m *MemoryCache) NewCache(str string) RecursionCache {
	s, _, _ := m.subStore.LoadOrCreate(str, func() (RecursionCache, error) {
		return &MemoryCache{}, nil
	})
	return s
}
