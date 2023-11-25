package singleflight

import (
	"fmt"

	"golang.org/x/sync/singleflight"
)

type Group[T any] struct {
	sf singleflight.Group
}

func (g *Group[T]) Do(key string, f func() (T, error)) (T, error) {
	v, err, _ := g.sf.Do(key, func() (any, error) { return f() })
	if err != nil {
		var t T
		return t, err
	}

	t, ok := v.(T)
	if !ok {
		return t, fmt.Errorf("value(%v[%T]) is not type: %T", v, v, t)
	}

	return t, nil
}
