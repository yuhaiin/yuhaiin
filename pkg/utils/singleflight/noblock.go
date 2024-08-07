package singleflight

import (
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

// call is an in-flight or completed singleflight.Do call
type callNoblock[T any] struct {
	funcs []func(T)
	fMu   sync.Mutex
}

func (c *callNoblock[T]) addFunc(fn func(T)) {
	c.fMu.Lock()
	c.funcs = append(c.funcs, fn)
	c.fMu.Unlock()
}

// Group represents a class of work and forms a namespace in
// which units of work can be executed with duplicate suppression.
type GroupNoblock[K comparable, V any] struct {
	m syncmap.SyncMap[K, *callNoblock[V]] // lazily initialized
}

// DoBackground executes and returns the results of the given function, making
// sure that only one execution is in-flight for a given key at a
// time. If a duplicate comes in, the duplicate caller waits for the
// original to complete and receives the same results.
// The return value shared indicates whether v was given to multiple callers.
func (g *GroupNoblock[K, V]) DoBackground(key K, f func(V), fn func() (V, bool)) {
	c, ok := g.m.Load(key)
	if !ok {
		c, ok = g.m.LoadOrStore(key, &callNoblock[V]{})
	}
	if ok {
		c.addFunc(f)
		return
	}

	go func() {
		val, ok := fn()
		if !ok {
			return
		}

		g.m.CompareAndDelete(key, c)

		f(val)

		c.fMu.Lock()
		funcs := c.funcs
		c.fMu.Unlock()

		for _, f := range funcs {
			f(val)
		}
	}()
}
