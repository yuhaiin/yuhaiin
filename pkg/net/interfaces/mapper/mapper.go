package mapper

type Mapper[K, K2, V any] interface {
	Insert(K, V)
	Search(K2) (V, bool)
	Clear() error
}
