package node

import (
	"container/heap"
	"context"
	"errors"
	"hash/fnv"
	"math/rand/v2"
	"sync"
	"time"
)

const maxProbeConcurrency = 16

type probeJob struct {
	group             string
	key, signature    string
	interval, timeout time.Duration
	cooldown          time.Duration
	failureThreshold  int
	jitter            float64
	concurrency       int
	run               func(context.Context) error
}

type scheduledProbe struct {
	probeJob
	next     time.Time
	index    int
	active   bool
	failures int
	cancel   context.CancelFunc
}

type probeQueue []*scheduledProbe

func (q probeQueue) Len() int { return len(q) }
func (q probeQueue) Less(i, j int) bool {
	if q[i].next.Equal(q[j].next) {
		return q[i].key < q[j].key
	}
	return q[i].next.Before(q[j].next)
}
func (q probeQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i]; q[i].index, q[j].index = i, j }
func (q *probeQueue) Push(x any)   { j := x.(*scheduledProbe); j.index = len(*q); *q = append(*q, j) }
func (q *probeQueue) Pop() any {
	old := *q
	j := old[len(old)-1]
	old[len(old)-1] = nil
	*q = old[:len(old)-1]
	j.index = -1
	return j
}

type probeWork struct {
	job *scheduledProbe
	ctx context.Context
}

type schedulerStatus struct {
	Skipped                uint64
	Jobs, Running, Workers int
	Completed, Failed      uint64
}

// A running job's limit applies until it finishes, even if another job in the
// same traffic class has a higher limit. Limits are capped at sixteen.
type probeGroup struct {
	running int
	limits  [maxProbeConcurrency + 1]int
}

func (g *probeGroup) canStart(limit int) bool {
	if g == nil {
		return true
	}
	if g.running >= limit {
		return false
	}
	for i := 1; i <= g.running; i++ {
		if g.limits[i] > 0 {
			return false
		}
	}
	return true
}

// probeScheduler owns a single queue timer and at most sixteen workers for the
// whole core. Inactive nodes have neither resident goroutines nor timers.
// replace cancels removed/changed work synchronously, including queued work.
// Matching keys coalesce identical node/target probes across selectors.
// Callbacks must honor their context; no forwarding operation runs a callback.
// All queue/state mutations are serialized independently of forwarding.
type probeScheduler struct {
	groups                  map[string]*probeGroup
	skipped                 uint64
	ctx                     context.Context
	cancel                  context.CancelFunc
	mu                      sync.Mutex
	jobs                    map[string]*scheduledProbe
	queue                   probeQueue
	work                    chan probeWork
	wake                    chan struct{}
	workers, limit, running int
	completed, failed       uint64
	closed                  bool
	wg                      sync.WaitGroup
}

func newProbeScheduler() *probeScheduler {
	ctx, cancel := context.WithCancel(context.Background())
	s := &probeScheduler{ctx: ctx, cancel: cancel, groups: map[string]*probeGroup{}, jobs: map[string]*scheduledProbe{}, work: make(chan probeWork, maxProbeConcurrency), wake: make(chan struct{}, 1)}
	s.wg.Go(s.loop)
	return s
}
func (s *probeScheduler) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *probeScheduler) replace(jobs []probeJob, limit int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	limit = max(1, min(limit, maxProbeConcurrency))
	s.limit = limit
	desired := make(map[string]probeJob, len(jobs))
	for _, j := range jobs {
		if j.interval <= 0 || j.timeout <= 0 || j.run == nil {
			continue
		}
		j.concurrency = max(1, min(j.concurrency, limit))
		if old, ok := desired[j.key]; !ok || j.interval < old.interval {
			desired[j.key] = j
		}
	}
	for key, old := range s.jobs {
		j, keep := desired[key]
		if keep && old.signature == j.signature && old.interval == j.interval && old.timeout == j.timeout && old.concurrency == j.concurrency && old.jitter == j.jitter && old.group == j.group {
			delete(desired, key)
			continue
		}
		if old.cancel != nil {
			old.cancel()
		}
		if old.index >= 0 {
			heap.Remove(&s.queue, old.index)
		}
		delete(s.jobs, key)
	}
	now := time.Now()
	for key, j := range desired {
		h := fnv.New64a()
		_, _ = h.Write([]byte(key))
		spread := min(j.interval, 5*time.Second)
		offset := time.Duration(h.Sum64() % uint64(max(spread, time.Nanosecond)))
		p := &scheduledProbe{probeJob: j, next: now.Add(offset), index: -1}
		s.jobs[key] = p
		heap.Push(&s.queue, p)
	}
	if len(s.jobs) > 0 {
		for s.workers < limit {
			s.workers++
			s.wg.Go(s.worker)
		}
	}
	s.signal()
}

func (s *probeScheduler) loop() {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		s.mu.Lock()
		var timerC <-chan time.Time
		if !s.closed {
			now := time.Now()
			var blocked []*scheduledProbe
			for s.running < s.limit && s.queue.Len() > 0 {
				j := s.queue[0]
				if j.next.After(now) {
					break
				}
				heap.Pop(&s.queue)
				group := s.groups[j.group]
				if !group.canStart(j.concurrency) {
					blocked = append(blocked, j)
					continue
				}
				if group == nil {
					group = &probeGroup{}
					s.groups[j.group] = group
				}
				ctx, cancel := context.WithTimeout(s.ctx, j.timeout)
				j.active, j.cancel = true, cancel
				s.running++
				group.running++
				group.limits[j.concurrency]++
				s.work <- probeWork{j, ctx}
			}
			// Jobs blocked by their concurrency cap wait for a completion/wake, not a
			// zero-duration timer spin. Other future jobs can still wake the queue.
			if s.queue.Len() > 0 && s.running < s.limit {
				timer.Reset(max(time.Until(s.queue[0].next), time.Nanosecond))
				timerC = timer.C
			}
			for _, j := range blocked {
				heap.Push(&s.queue, j)
			}
		}
		s.mu.Unlock()
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
			if timerC != nil {
				timer.Stop()
			}
		case <-timerC:
		}
	}
}
func (s *probeScheduler) worker() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case work := <-s.work:
			err := work.ctx.Err()
			if err == nil {
				err = work.job.run(work.ctx)
			}
			s.mu.Lock()
			work.job.cancel()
			work.job.active = false
			work.job.cancel = nil
			s.running--
			group := s.groups[work.job.group]
			group.running--
			group.limits[work.job.concurrency]--
			if group.running == 0 {
				delete(s.groups, work.job.group)
			}
			s.completed++
			if errors.Is(err, errProbeSkipped) || errors.Is(err, context.Canceled) {
				s.skipped++
			} else if err != nil {
				s.failed++
			}
			if s.jobs[work.job.key] == work.job && !s.closed {
				if err == nil {
					work.job.failures = 0
				} else if !errors.Is(err, errProbeSkipped) && !errors.Is(err, context.Canceled) {
					work.job.failures++
				}
				interval := work.job.interval
				if work.job.failures >= max(1, work.job.failureThreshold) {
					interval = max(interval, work.job.cooldown)
				}
				jitter := 1 + (rand.Float64()*2-1)*work.job.jitter
				delay := time.Duration(float64(interval) * jitter)
				if work.job.failures >= max(1, work.job.failureThreshold) {
					delay = max(delay, work.job.cooldown)
				}
				work.job.next = time.Now().Add(delay)
				heap.Push(&s.queue, work.job)
			}
			s.mu.Unlock()
			s.signal()
		}
	}
}
func (s *probeScheduler) status() schedulerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return schedulerStatus{Jobs: len(s.jobs), Running: s.running, Workers: s.workers, Completed: s.completed, Failed: s.failed, Skipped: s.skipped}
}
func (s *probeScheduler) close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.cancel()
		for _, j := range s.jobs {
			if j.cancel != nil {
				j.cancel()
			}
		}
	}
	s.mu.Unlock()
	s.wg.Wait()
}
