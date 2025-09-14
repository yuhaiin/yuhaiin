package semaphore

import (
	"context"

	"golang.org/x/sync/semaphore"
)

type Semaphore interface {
	Acquire(ctx context.Context, n int64) error
	TryAcquire(n int64) bool
	Release(n int64)
	Weight() int64
}

type EmptySemaphore struct{}

func (e *EmptySemaphore) Acquire(ctx context.Context, n int64) error { return nil }
func (e *EmptySemaphore) TryAcquire(n int64) bool                    { return true }
func (e *EmptySemaphore) Release(n int64)                            {}
func (e *EmptySemaphore) Weight() int64                              { return 0 }

func NewEmptySemaphore() Semaphore {
	return &EmptySemaphore{}
}

// NewSemaphore returns a semaphore with n permits.
// If n <= 0, it returns an empty semaphore.
func NewSemaphore(n int64) Semaphore {
	if n <= 0 {
		return NewEmptySemaphore()
	}
	return &WeightedSemaphore{Weighted: semaphore.NewWeighted(n), weight: n}
}

type WeightedSemaphore struct {
	*semaphore.Weighted
	weight int64
}

func (s *WeightedSemaphore) Weight() int64 { return s.weight }
