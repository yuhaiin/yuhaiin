package quota

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSettledShutdownReturnsUnusedDurableCredits(t *testing.T) {
	store := newMemoryStore()
	l := New(store)
	b := binding("user", "alice", "1000")
	b.Quota.Period = "lifetime"
	p := prepare(t, l, b)
	var r Reservation
	if _, err := reserveWait(t.Context(), p, Upload, 123, true, &r); err != nil {
		t.Fatal(err)
	}
	r.Commit(123)
	if err := l.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	restarted := newTestLedger(t, store)
	next := prepare(t, restarted, b)
	u := next.Usage()[0]
	if u.Used.Combined != "123" || u.RecoveryCharge.Combined != "0" || u.Remaining.Combined != "877" {
		t.Fatalf("clean restart charged unused credit: %+v", u)
	}
}

func TestRetiredQuotaReclaimsWithoutResettingUsage(t *testing.T) {
	store := newMemoryStore()
	l := newTestLedger(t, store)
	b := binding("user", "alice", "1000")
	b.Quota.Period = "lifetime"
	p := prepare(t, l, b)
	var r Reservation
	if _, err := reserveWait(t.Context(), p, Upload, 200, true, &r); err != nil {
		t.Fatal(err)
	}
	r.Commit(200)
	l.RetireUnused(func(Key) bool { return false })
	if _, _, err := p.TryReserve(time.Now(), Upload, 1, true, &r); !errors.Is(err, ErrRetired) {
		t.Fatal("retired handle continued admitting", err)
	}
	if err := l.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := l.Diagnostics().Windows; n != 0 {
		t.Fatalf("retired state retained: %d", n)
	}
	next := prepare(t, l, b)
	if u := next.Usage()[0]; u.Used.Combined != "200" || u.RecoveryCharge.Combined != "0" {
		t.Fatalf("reactivation reset or overcharged usage: %+v", u)
	}
	if _, err := reserveWait(t.Context(), next, Download, 800, true, &r); err != nil {
		t.Fatal(err)
	}
	r.Commit(800)
	if _, _, err := p.TryReserve(time.Now(), Upload, 1, true, &r); !errors.Is(err, ErrRetired) {
		t.Fatal("stale plan accessed a reactivated budget", err)
	}
}

func TestCloseReclaimsAnUnacknowledgedUnusedGrant(t *testing.T) {
	store := newMemoryStore()
	store.lostAck.Store(true)
	l := New(store)
	p := prepare(t, l, binding("user", "alice", "1000"))
	var r Reservation
	if _, _, err := p.TryReserve(time.Now(), Upload, 1, true, &r); !errors.Is(err, ErrFunding) {
		t.Fatal(err)
	}
	until := time.Now().Add(5 * time.Second)
	for store.saves.Load() == 0 {
		if time.Now().After(until) {
			t.Fatal("funding never attempted")
		}
		time.Sleep(time.Millisecond)
	}
	if err := l.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, e := range p.entries {
		record, err := store.Load(t.Context(), e.w.record.Key)
		if err != nil || record.Charged != (Amounts{}) {
			t.Fatalf("unused ambiguous grant retained: %+v %v", record, err)
		}
	}
}
