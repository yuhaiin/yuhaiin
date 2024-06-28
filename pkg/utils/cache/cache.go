package cache

type Cache interface {
	Get(k []byte) (v []byte)
	Put(k, v []byte)
	Delete(k ...[]byte)
	Close() error
	Range(f func(key []byte, value []byte) bool)
}
