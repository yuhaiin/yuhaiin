package mapper

import "errors"

type Mapper[K, K2, V any] interface {
	Insert(K, V)
	Search(K2) (V, bool)
	Clear() error
}

var ErrSkipResolveDomain = errors.New("skip resolver domain")
