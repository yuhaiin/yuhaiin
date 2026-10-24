package quota

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
)

type memoryStore struct {
	mu      sync.Mutex
	records map[Key]Record
	fail    atomic.Bool
	lostAck atomic.Bool
	saves   atomic.Uint64
}

func newMemoryStore() *memoryStore { return &memoryStore{records: make(map[Key]Record)} }
func (s *memoryStore) Load(_ context.Context, key Key) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[key]
	if !ok {
		r.Key = key
	}
	return r, nil
}
func (s *memoryStore) Save(_ context.Context, records []Record) error {
	s.saves.Add(1)
	if s.fail.Load() {
		return errors.New("disk unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range records {
		old := s.records[r.Key]
		old.Key = r.Key
		old.OwnerUserID = r.OwnerUserID
		old.Denied = max(old.Denied, r.Denied)
		for i := range old.Measured {
			old.Measured[i] = max(old.Measured[i], r.Measured[i])
			old.Charged[i] = max(old.Charged[i], r.Charged[i])
		}
		for i := range old.Alerts {
			old.Alerts[i] |= r.Alerts[i]
		}
		s.records[r.Key] = old
	}
	if s.lostAck.Swap(false) {
		return errors.New("lost commit acknowledgement")
	}
	return nil
}

func (s *memoryStore) Reclaim(_ context.Context, requests []Reclaim) error {
	if s.fail.Load() {
		return errors.New("disk unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, request := range requests {
		old := s.records[request.Record.Key]
		for i, n := range old.Charged {
			if n < request.Record.Charged[i] || n > request.MaxCharged[i] {
				return errors.New("reclaim counter conflict")
			}
		}
	}
	for _, request := range requests {
		s.records[request.Record.Key] = request.Record
	}
	return nil
}

func binding(scope, id, size string) Binding {
	return Binding{Scope: scope, ScopeID: id, Quota: resource.Quota{ID: "quota-" + id, Period: "daily", Combined: size, Action: "terminate", Thresholds: []int{80, 90, 100}}}
}
func newTestLedger(t *testing.T, store Store) *Ledger {
	t.Helper()
	l := New(store)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := l.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return l
}
func prepare(t testing.TB, l *Ledger, bindings ...Binding) *Plan {
	t.Helper()
	p, err := l.Prepare(t.Context(), bindings, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func reserveWait(ctx context.Context, p *Plan, direction Direction, n int, whole bool, r *Reservation) (int, error) {
	for {
		granted, ready, err := p.TryReserve(time.Now(), direction, n, whole, r)
		if !errors.Is(err, ErrFunding) {
			return granted, err
		}
		select {
		case <-ready:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

func TestConcurrentSharedQuotaNoOvershoot(t *testing.T) {
	l := newTestLedger(t, newMemoryStore())
	group := binding("group", "shared", "10000")
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := range 128 {
		p := prepare(t, l, binding("user", strconv.Itoa(i), "1000"), group)
		wg.Go(func() {
			for range 100 {
				var r Reservation
				n, err := reserveWait(t.Context(), p, Upload, 1, true, &r)
				if errors.Is(err, ErrExhausted) {
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
				r.Commit(n)
				accepted.Add(int64(n))
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 10000 {
		t.Fatalf("accepted %d, want exactly 10000", accepted.Load())
	}
	u := prepare(t, l, group).Usage()[0]
	if u.Used.Combined != "10000" || u.Remaining.Combined != "0" {
		t.Fatalf("usage: %+v", u)
	}
}

func TestAtomicScopesShortWriteAndDirectionBudgets(t *testing.T) {
	l := newTestLedger(t, newMemoryStore())
	u, g := binding("user", "alice", "100"), binding("group", "finance", "70")
	u.Quota.Upload, u.Quota.Download = "60", "50"
	p := prepare(t, l, g, u)
	var r Reservation
	if n, err := reserveWait(t.Context(), p, Upload, 60, true, &r); n != 60 || err != nil {
		t.Fatalf("reserve: %d %v", n, err)
	}
	r.Commit(20)
	r.Commit(60) // A repeated completion cannot charge or refund twice.
	if _, err := reserveWait(t.Context(), p, Download, 51, true, &r); !errors.Is(err, ErrExhausted) {
		t.Fatalf("oversize datagram: %v", err)
	}
	n, err := reserveWait(t.Context(), p, Download, 60, false, &r)
	if err != nil || n != 50 {
		t.Fatalf("partial TCP grant: %d %v", n, err)
	}
	r.Commit(n)
	if _, err := reserveWait(t.Context(), p, Upload, 1, true, &r); !errors.Is(err, ErrExhausted) {
		t.Fatalf("group combined budget: %v", err)
	}
	for _, usage := range p.Usage() {
		if usage.Used.Upload != "20" || usage.Used.Download != "50" || usage.Used.Combined != "70" {
			t.Fatalf("double or failed accounting: %+v", usage)
		}
	}
}

func TestRecoveryConservativelyChargesUnconfirmedCredit(t *testing.T) {
	store := newMemoryStore()
	l := New(store)
	b := binding("user", "alice", "1000")
	p := prepare(t, l, b)
	var r Reservation
	if _, err := reserveWait(t.Context(), p, Upload, 123, true, &r); err != nil {
		t.Fatal(err)
	}
	r.Commit(123)
	// Stop without checkpoint to simulate an abrupt process loss.
	l.closed.Store(true)
	l.cancel()
	<-l.done
	restarted := newTestLedger(t, store)
	recovered := prepare(t, restarted, b)
	u := recovered.Usage()[0]
	if u.Used.Combined != "1000" || u.RecoveryCharge.Combined != "1000" || u.Measured.Combined != "0" {
		t.Fatalf("recovery lost a durable grant: %+v", u)
	}
	if _, _, err := recovered.TryReserve(time.Now(), Download, 1, true, &r); !errors.Is(err, ErrExhausted) {
		t.Fatalf("recovery bypassed quota: %v", err)
	}
}

func TestPersistenceFailureAndLostAcknowledgement(t *testing.T) {
	store := newMemoryStore()
	l := newTestLedger(t, store)
	p := prepare(t, l, binding("user", "alice", "1000"))
	store.fail.Store(true)
	var r Reservation
	_, ready, err := p.TryReserve(time.Now(), Upload, 1, true, &r)
	if !errors.Is(err, ErrFunding) || ready == nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
		t.Fatal("unpersisted credit was published")
	case <-time.After(150 * time.Millisecond):
	}
	if l.Diagnostics().Pending != 1 || l.Diagnostics().PersistenceFailures == 0 {
		t.Fatalf("unobservable failure: %+v", l.Diagnostics())
	}
	store.lostAck.Store(true)
	store.fail.Store(false)
	if n, err := reserveWait(t.Context(), p, Upload, 1000, true, &r); err != nil || n != 1000 {
		t.Fatalf("idempotent retry: %d %v", n, err)
	}
	r.Commit(1000)
	if p.Usage()[0].Used.Combined != "1000" {
		t.Fatal("retry duplicated accounting")
	}
}

func TestThresholdsWarnAndAlertDeduplication(t *testing.T) {
	l := newTestLedger(t, newMemoryStore())
	b := binding("user", "alice", "100")
	b.Quota.Action = "warn"
	p := prepare(t, l, b)
	for range 110 {
		var r Reservation
		if _, err := reserveWait(t.Context(), p, Upload, 1, true, &r); err != nil {
			t.Fatal(err)
		}
		r.Commit(1)
	}
	counts := map[int]int{}
	for len(l.events) > 0 {
		counts[(<-l.events).Threshold]++
	}
	for _, threshold := range []int{80, 90, 100} {
		if counts[threshold] != 1 {
			t.Fatalf("threshold events: %v", counts)
		}
	}
	if !p.Usage()[0].Exceeded || p.Usage()[0].Used.Combined != "110" {
		t.Fatal("warn policy blocked traffic")
	}
	b.Quota.Thresholds = []int{100, 80, 90}
	p = prepare(t, l, b)
	var r Reservation
	if _, err := reserveWait(t.Context(), p, Upload, 1, true, &r); err != nil {
		t.Fatal(err)
	}
	r.Commit(1)
	if len(l.events) != 0 {
		t.Fatal("threshold reordering replayed alerts")
	}
}

func TestUTCWindowsAndExpiredPlan(t *testing.T) {
	at := time.Date(2028, 2, 29, 23, 59, 59, 0, time.UTC)
	for _, period := range []string{"daily", "monthly"} {
		_, end, err := Window(period, at.In(time.FixedZone("offset", 8*3600)))
		if err != nil || end != at.Add(time.Second).Unix() {
			t.Fatalf("%s: %d %v", period, end, err)
		}
	}
	l := newTestLedger(t, newMemoryStore())
	b := binding("user", "alice", "100")
	p, err := l.Prepare(t.Context(), []Binding{b}, at)
	if err != nil {
		t.Fatal(err)
	}
	var r Reservation
	if _, _, err := p.TryReserve(at.Add(time.Second), Upload, 1, true, &r); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	next, err := l.Prepare(t.Context(), []Binding{b}, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if next.Usage()[0].Used.Combined != "0" {
		t.Fatal("new UTC window inherited old counters")
	}
}

func BenchmarkQuotaReservation(b *testing.B) {
	l := New(newMemoryStore())
	b.Cleanup(func() { _ = l.Close(context.Background()) })
	p := prepare(b, l, binding("user", "alice", "9223372036854775807"), binding("group", "shared", "9223372036854775807"))
	var r Reservation
	// Refund each reservation to isolate the funded fast path from persistence.
	if _, err := reserveWait(b.Context(), p, Upload, 1350, true, &r); err != nil {
		b.Fatal(err)
	}
	r.Commit(0)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := p.TryReserve(time.Now(), Upload, 1350, true, &r); err != nil {
			b.Fatal(err)
		}
		r.Commit(0)
	}
}
