package control

import "context"

type ServerStream[T any] interface {
	Send(*T) error
	Context() context.Context
}
