package quota

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestOutstandingReservationsCannotExpandCrashUncertainty(t *testing.T) {
	store := newMemoryStore()
	l := newTestLedger(t, store)
	p := prepare(t, l, binding("user", "alice", strconv.FormatUint(GrantBytes*4, 10)))
	tickets := make([]Reservation, GrantBytes/MaxReservationBytes)
	for i := range tickets {
		if n, err := reserveWait(t.Context(), p, Upload, MaxReservationBytes, true, &tickets[i]); err != nil || n != MaxReservationBytes {
			t.Fatalf("reserve %d: %d %v", i, n, err)
		}
	}
	var next Reservation
	_, ready, err := p.TryReserve(time.Now(), Upload, 1, true, &next)
	if !errors.Is(err, ErrFunding) || ready == nil {
		t.Fatalf("outstanding credit should wait: %v", err)
	}
	select {
	case <-ready:
		t.Fatal("minted additional unconfirmed credit")
	default:
	}
	for i := range tickets {
		tickets[i].Commit(0)
	}
	select {
	case <-ready:
	default:
		t.Fatal("refunded credit did not wake waiter")
	}
	if n, err := reserveWait(t.Context(), p, Upload, 1, true, &next); err != nil || n != 1 {
		t.Fatalf("refunded reservation: %d %v", n, err)
	}
	next.Commit(1)
	for _, e := range p.entries {
		record, err := store.Load(t.Context(), e.w.record.Key)
		if err != nil {
			t.Fatal(err)
		}
		for i := range record.Charged {
			if record.Charged[i]-record.Measured[i] > GrantBytes {
				t.Fatalf("crash uncertainty exceeded one grant: %+v", record)
			}
		}
	}
}

func TestHardQuotaWaiterWakesOnRefund(t *testing.T) {
	l := newTestLedger(t, newMemoryStore())
	p := prepare(t, l, binding("user", "alice", "100"))
	var a, b Reservation
	if _, err := reserveWait(t.Context(), p, Upload, 100, true, &a); err != nil {
		t.Fatal(err)
	}
	_, ready, err := p.TryReserve(time.Now(), Download, 1, true, &b)
	if !errors.Is(err, ErrExhausted) || ready == nil {
		t.Fatal("in-flight quota denial has no notification")
	}
	a.Commit(40)
	select {
	case <-ready:
	default:
		t.Fatal("refund did not wake exhausted waiter")
	}
	if n, err := reserveWait(t.Context(), p, Download, 60, true, &b); err != nil || n != 60 {
		t.Fatalf("refunded combined allowance: %d %v", n, err)
	}
	b.Commit(60)
}
