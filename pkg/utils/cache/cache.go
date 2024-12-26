package cache

import "errors"

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

var _ Cache = (*MockCache)(nil)

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
func (m *MockCache) NewCache(str string) Cache                         { return &MockCache{} }
func NewMockCache() Cache                                              { return &MockCache{} }

var ErrBucketNotExist = errors.New("bucket not exist")
