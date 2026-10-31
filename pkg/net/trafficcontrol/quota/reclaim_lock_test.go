package quota

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
)

type blockingReclaimStore struct {
	*memoryStore
	entered, release chan struct{}
}

func (s *blockingReclaimStore) Reclaim(ctx context.Context, requests []Reclaim) error {
	s.entered <- struct{}{}
	<-s.release
	return s.memoryStore.Reclaim(ctx, requests)
}

func fundedPlan(t *testing.T, l *Ledger) *Plan {
	t.Helper()
	bindings := []Binding{}
	for _, id := range []string{"a", "b", "c", "d", "e", "f"} {
		bindings = append(bindings, Binding{Scope: "user", ScopeID: "u" + id, Quota: resource.Quota{ID: "q" + id, Period: "lifetime", Action: "block_new", Combined: "1000000000"}})
	}
	now := time.Now()
	p, err := l.Prepare(t.Context(), bindings, now)
	if err != nil {
		t.Fatal(err)
	}
	for {
		var ticket Reservation
		_, ready, err := p.TryReserve(now, Upload, 1, false, &ticket)
		if err == nil {
			ticket.Commit(1)
			return p
		}
		if ready == nil {
			t.Fatal(err)
		}
		<-ready
	}
}

func TestReclaimHoldsNoWindowLockAcrossStorage(t *testing.T) {
	store := &blockingReclaimStore{memoryStore: newMemoryStore(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	l := New(store)
	defer func() { _ = l.Close(context.Background()) }()
	p := fundedPlan(t, l)
	l.RetireUnused(func(Key) bool { return false })
	flushed := make(chan error, 1)
	go func() { flushed <- l.Flush(context.Background()) }()
	select {
	case <-store.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("reclaim did not reach storage")
	}
	usage := make(chan struct{})
	go func() { p.Usage(); close(usage) }()
	select {
	case <-usage:
	case <-time.After(5 * time.Second):
		t.Fatal("a slow reclaim blocked a plan on its window lock")
	}
	close(store.release)
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
}

func TestReclaimCannotDeadlockWithPlanLockOrder(t *testing.T) {
	store := newMemoryStore()
	for range 50 {
		l := New(store)
		p := fundedPlan(t, l)
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
						p.Usage()
					}
				}
			})
		}
		l.RetireUnused(func(Key) bool { return false })
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		err := l.Flush(ctx)
		cancel()
		if err != nil {
			t.Fatal("reclaim deadlocked:", err)
		}
		close(stop)
		wg.Wait()
		if err := l.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		store = newMemoryStore()
	}
}

func TestReclaimReturnsUnusedCreditAndForgetsRetiredWindow(t *testing.T) {
	store := newMemoryStore()
	l := New(store)
	defer func() { _ = l.Close(context.Background()) }()
	fundedPlan(t, l)
	l.RetireUnused(func(Key) bool { return false })
	if err := l.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := l.Diagnostics().Windows; n != 0 {
		t.Fatal("reclaimed windows remain", n)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.records) != 6 {
		t.Fatal(len(store.records))
	}
	for key, r := range store.records {
		if r.Charged != r.Measured {
			t.Fatal("unused credit was retained", key, r.Charged, r.Measured)
		}
	}
}
