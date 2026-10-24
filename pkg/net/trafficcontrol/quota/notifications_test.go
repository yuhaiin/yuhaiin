package quota

import (
	"testing"
	"time"
)

func TestRecoveredExhaustionNotifiesOnlyAfterActivation(t *testing.T) {
	store := newMemoryStore()
	b := binding("user", "alice", "100")
	b.Quota.Period = "lifetime"
	k := Key{Scope: "user", ScopeID: "alice", QuotaID: b.Quota.ID, Period: "lifetime"}
	store.records[k] = Record{Key: k, OwnerUserID: "alice", Charged: Amounts{100, 0, 100}}
	l := newTestLedger(t, store)
	p := prepare(t, l, b)
	if len(l.events) != 0 || len(l.terminations) != 0 {
		t.Fatal("draft preparation emitted operational notifications")
	}
	p.NotifyOwned()
	if len(l.events) != 3 || len(l.terminations) != 1 {
		t.Fatal("recovered exhausted counters were not notified")
	}
	<-l.terminations
	for range 3 {
		<-l.events
	}
	p.NotifyOwned()
	if len(l.events) != 0 || len(l.terminations) != 0 {
		t.Fatal("activation replayed an already emitted notification")
	}
	if effects, err := p.Effects(time.Now()); err != nil || !effects.Terminate {
		t.Fatal("recovery did not enforce termination", effects, err)
	}
}

func TestActivatedThresholdUsesCurrentLimitsWithoutNewTraffic(t *testing.T) {
	l := newTestLedger(t, newMemoryStore())
	b := binding("user", "alice", "1000")
	b.Quota.Action, b.Quota.Thresholds = "warn", []int{100}
	p := prepare(t, l, b)
	var r Reservation
	if _, err := reserveWait(t.Context(), p, Upload, 90, true, &r); err != nil {
		t.Fatal(err)
	}
	r.Commit(90)
	b.Quota.Combined, b.Quota.Thresholds = "100", []int{80, 90, 100}
	next := prepare(t, l, b)
	if len(l.events) != 0 {
		t.Fatal("draft changes emitted alerts")
	}
	next.NotifyOwned()
	if len(l.events) != 2 {
		t.Fatal("newly active thresholds require unrelated traffic")
	}
}
