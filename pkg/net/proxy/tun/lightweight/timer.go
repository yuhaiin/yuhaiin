package lightweight

import (
	"container/heap"
	"sync"
	"time"
)

// Lock order: connection/fragment lock -> scheduler lock. The scheduler always
// removes a job and releases its lock before invoking protocol code. One heap
// entry per connection serves pacing, RTO, persist, delayed ACK and teardown.
type timerJob struct {
	at    time.Time
	index int
	run   func(time.Time)
}
type jobHeap []*timerJob

func (h jobHeap) Len() int           { return len(h) }
func (h jobHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h jobHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *jobHeap) Push(v any)        { j := v.(*timerJob); j.index = len(*h); *h = append(*h, j) }
func (h *jobHeap) Pop() any {
	a := *h
	j := a[len(a)-1]
	a[len(a)-1] = nil
	*h = a[:len(a)-1]
	j.index = -1
	return j
}

type scheduler struct {
	mu   sync.Mutex
	jobs jobHeap
	wake chan struct{}
	done <-chan struct{}
}

func newScheduler(done <-chan struct{}) *scheduler {
	return &scheduler{wake: make(chan struct{}, 1), done: done}
}
func (q *scheduler) set(j *timerJob, at time.Time) {
	q.mu.Lock()
	if at.IsZero() {
		if j.index >= 0 {
			heap.Remove(&q.jobs, j.index)
		}
	} else {
		j.at = at
		if j.index >= 0 {
			heap.Fix(&q.jobs, j.index)
		} else {
			heap.Push(&q.jobs, j)
		}
	}
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}
func (q *scheduler) loop() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		q.mu.Lock()
		var wait <-chan time.Time
		if len(q.jobs) > 0 {
			d := time.Until(q.jobs[0].at)
			if d <= 0 {
				j := heap.Pop(&q.jobs).(*timerJob)
				q.mu.Unlock()
				select {
				case <-q.done:
					return
				default:
				}
				j.run(time.Now())
				continue
			}
			timer.Reset(d)
			wait = timer.C
		} else {
			timer.Stop()
		}
		q.mu.Unlock()
		select {
		case <-q.done:
			return
		case <-q.wake:
		case <-wait:
		}
	}
}
func earliest(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}
