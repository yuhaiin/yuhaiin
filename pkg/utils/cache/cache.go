package cache

import (
	"errors"
	"iter"
)

func Element(key []byte, value []byte) iter.Seq2[[]byte, []byte] {
	return func(yield func([]byte, []byte) bool) {
		_ = yield(key, value)
	}
}

type Cache interface {
	Get(k []byte) (v []byte, err error)
	Put(iter.Seq2[[]byte, []byte]) error
	Delete(k ...[]byte) error
	Range(f func(key []byte, value []byte) bool) error
	NewCache(str ...string) Cache
}

var _ Cache = (*MockCache)(nil)

type MockCache struct {
	OnPut func(k, v []byte)
}

func (m *MockCache) Get(k []byte) (v []byte, _ error) { return nil, nil }
func (m *MockCache) Put(es iter.Seq2[[]byte, []byte]) error {
	if m.OnPut != nil {
		for k, v := range es {
			m.OnPut(k, v)
		}
	}
	return nil
}
func (m *MockCache) Delete(k ...[]byte) error                          { return nil }
func (m *MockCache) Range(f func(key []byte, value []byte) bool) error { return nil }
func (m *MockCache) Close() error                                      { return nil }
func (m *MockCache) NewCache(str ...string) Cache                      { return &MockCache{} }
func NewMockCache() Cache                                              { return &MockCache{} }

var ErrBucketNotExist = errors.New("bucket not exist")
