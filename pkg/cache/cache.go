package cache

import (
	"errors"
	"time"
)

type PutOptions struct {
	TTL time.Duration
}

// WithTTL only badger cache support TTL
func WithTTL(ttl time.Duration) func(*PutOptions) {
	return func(o *PutOptions) {
		o.TTL = ttl
	}
}

func GetPutOptions(opts ...func(*PutOptions)) *PutOptions {
	o := &PutOptions{}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

type Batch interface {
	Put(k []byte, v []byte, opts ...func(*PutOptions)) error
	Delete(k []byte) error
	// response only valid when batch
	Get(k []byte) ([]byte, error)
}

type Cache interface {
	Get(k []byte) (v []byte, err error)
	Put([]byte, []byte, ...func(*PutOptions)) error
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
func (m *MockCache) Put(k []byte, v []byte, opts ...func(*PutOptions)) error {
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
