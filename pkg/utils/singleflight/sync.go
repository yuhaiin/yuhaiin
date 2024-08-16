package singleflight

import (
	"context"
	"runtime"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

// call is an in-flight or completed singleflight.Do call
type callSync[T any] struct {

	// These fields are written once before the WaitGroup is done
	// and are only read after the WaitGroup is done.
	val T
	err error

	done chan struct{} // closed when fn is done

	// These fields are read and written with the singleflight
	// mutex held before the WaitGroup is done, and are read but
	// not written after the WaitGroup is done.
	dups atomic.Int64
}

// Group represents a class of work and forms a namespace in
// which units of work can be executed with duplicate suppression.
type GroupSync[K comparable, V any] struct {
	m syncmap.SyncMap[K, *callSync[V]] // lazily initialized
}

// Do executes and returns the results of the given function, making
// sure that only one execution is in-flight for a given key at a
// time. If a duplicate comes in, the duplicate caller waits for the
// original to complete and receives the same results.
// The return value shared indicates whether v was given to multiple callers.
func (g *GroupSync[K, V]) Do(ctx context.Context, key K, fn func(context.Context) (V, error)) (v V, err error, shared bool) {
	c, ok := g.m.Load(key)
	if !ok {
		c, ok = g.m.LoadOrStore(key, &callSync[V]{done: make(chan struct{})})
	}
	if ok {
		c.dups.Add(1)
		select {
		case <-ctx.Done():
			return v, ctx.Err(), false
		case <-c.done:
		}

		if e, ok := c.err.(*panicError); ok {
			panic(e)
		} else if c.err == errGoexit {
			runtime.Goexit()
		}
		return c.val, c.err, true
	}

	g.doCallSync(ctx, c, key, fn)
	return c.val, c.err, c.dups.Load() > 0
}

// doCall handles the single call for a key.
func (g *GroupSync[K, V]) doCallSync(ctx context.Context, c *callSync[V], key K, fn func(context.Context) (V, error)) {
	normalReturn := false
	recovered := false

	// use double-defer to distinguish panic from runtime.Goexit,
	// more details see https://golang.org/cl/134395
	defer func() {
		// the given function invoked runtime.Goexit
		if !normalReturn && !recovered {
			c.err = errGoexit
		}

		close(c.done)
		g.m.CompareAndDelete(key, c)

		if e, ok := c.err.(*panicError); ok {
			panic(e)
		}
	}()

	func() {
		defer func() {
			if !normalReturn {
				// Ideally, we would wait to take a stack trace until we've determined
				// whether this is a panic or a runtime.Goexit.
				//
				// Unfortunately, the only way we can distinguish the two is to see
				// whether the recover stopped the goroutine from terminating, and by
				// the time we know that, the part of the stack trace relevant to the
				// panic has been discarded.
				if r := recover(); r != nil {
					c.err = newPanicError(r)
				}
			}
		}()

		c.val, c.err = fn(ctx)
		normalReturn = true
	}()

	if !normalReturn {
		recovered = true
	}
}
