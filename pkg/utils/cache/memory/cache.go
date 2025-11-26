package memory

import (
	"iter"

	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var _ cache.Cache = (*MemoryCache)(nil)

type MemoryCache struct {
	cache    syncmap.SyncMap[string, []byte]
	subStore syncmap.SyncMap[string, *MemoryCache]
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{}
}

func (m *MemoryCache) Get(k []byte) (v []byte, err error) {
	x, _ := m.cache.Load(string(k))
	return x, nil
}

func (m *MemoryCache) Put(es iter.Seq2[[]byte, []byte]) error {
	for k, v := range es {
		m.cache.Store(string(k), v)
	}
	return nil
}

func (m *MemoryCache) Delete(k iter.Seq[[]byte]) error {
	for k := range k {
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

func (m *MemoryCache) loadOrCreateBucket(str string) *MemoryCache {
	s, _, _ := m.subStore.LoadOrCreate(str, func() (*MemoryCache, error) {
		return &MemoryCache{}, nil
	})
	return s
}

func (m *MemoryCache) NewCache(str ...string) cache.Cache {
	z := m
	for _, v := range str {
		z = z.loadOrCreateBucket(v)
	}
	return z
}

func (m *MemoryCache) DeleteBucket(str ...string) error {
	if len(str) == 0 {
		return nil
	}
	z := m
	for _, v := range str[:len(str)-1] {
		z = z.loadOrCreateBucket(v)
	}
	z.subStore.Delete(str[len(str)-1])
	return nil
}
