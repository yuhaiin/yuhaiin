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

type Batch interface {
	Put(k []byte, v []byte) error
	Delete(k []byte) error
	// response only valid when batch
	Get(k []byte) ([]byte, error)
}

type Cache interface {
	Get(k []byte) (v []byte, err error)
	Put([]byte, []byte) error
	Delete(k []byte) error
	Range(f func(key []byte, value []byte) bool) error
	NewCache(str ...string) Cache
	DeleteBucket(str ...string) error

	Batch(f func(txn Batch) error) error
}

var _ Cache = (*MockCache)(nil)

type MockCache struct {
	OnPut func(k, v []byte)
}

func (m *MockCache) Get(k []byte) (v []byte, _ error) { return nil, nil }
func (m *MockCache) Put(k []byte, v []byte) error {
	if m.OnPut != nil {
		m.OnPut(k, v)
	}
	return nil
}
func (m *MockCache) Delete(k []byte) error                             { return nil }
func (m *MockCache) Range(f func(key []byte, value []byte) bool) error { return nil }
func (m *MockCache) NewCache(str ...string) Cache                      { return &MockCache{} }
func (m *MockCache) DeleteBucket(str ...string) error                  { return nil }
func (m *MockCache) Batch(f func(txn Batch) error) error               { return nil }
func NewMockCache() Cache                                              { return &MockCache{} }

var ErrBucketNotExist = errors.New("bucket not exist")
