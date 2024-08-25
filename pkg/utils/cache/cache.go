package cache

type Cache interface {
	Get(k []byte) (v []byte)
	Put(k, v []byte)
	Delete(k ...[]byte)
	Close() error
	Range(f func(key []byte, value []byte) bool)
}

var _ Cache = (*MockCache)(nil)

type MockCache struct {
	OnPut func(k, v []byte)
}

func (m *MockCache) Get(k []byte) (v []byte) { return nil }
func (m *MockCache) Put(k, v []byte) {
	if m.OnPut != nil {
		m.OnPut(k, v)
	}
}
func (m *MockCache) Delete(k ...[]byte)                          {}
func (m *MockCache) Range(f func(key []byte, value []byte) bool) {}
func (m *MockCache) Close() error                                { return nil }
func NewMockCache() Cache                                        { return &MockCache{} }
