package mapper

type Mapper[K, V any] interface {
	Insert(K, V)
	Search(K) (V, bool)
	Clear() error
}
