package auth

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

func TestQuotaStoreIdempotentAndAtomic(t *testing.T) {
	s := quotaStore{db: testStore(t).db}
	key := quota.Key{Scope: "user", ScopeID: "historical-user", QuotaID: "daily", Period: "daily", StartsAt: 86400}
	r := quota.Record{OwnerUserID: key.ScopeID, Key: key, Measured: quota.Amounts{12, 8, 20}, Charged: quota.Amounts{100, 100, 100}, Alerts: [2]uint64{1 << 63, 1 << 36}}
	for range 2 {
		if err := s.Save(t.Context(), []quota.Record{r}); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := s.Load(t.Context(), key)
	if err != nil || loaded != r {
		t.Fatalf("checkpoint changed on retry: %+v %v", loaded, err)
	}
	older := r
	older.Measured = quota.Amounts{}
	older.Charged = quota.Amounts{50, 50, 50}
	if err := s.Save(t.Context(), []quota.Record{older}); err != nil {
		t.Fatal(err)
	}
	loaded, err = s.Load(t.Context(), key)
	if err != nil || loaded != r {
		t.Fatalf("stale retry rolled counters back: %+v %v", loaded, err)
	}

	updated := r
	updated.Measured = quota.Amounts{20, 20, 40}
	invalid := r
	invalid.Key.Period = "monthly"
	if err := s.Save(t.Context(), []quota.Record{updated, invalid}); err == nil {
		t.Fatal("changed quota period reused old ID")
	}
	loaded, err = s.Load(t.Context(), key)
	if err != nil || loaded != r {
		t.Fatalf("partially committed batch: %+v %v", loaded, err)
	}
	if _, err := s.Load(t.Context(), invalid.Key); err == nil {
		t.Fatal("different period bypassed durable owner binding")
	}
}

func TestQuotaStoreRestartAndThresholdBits(t *testing.T) {
	s := quotaStore{db: testStore(t).db}
	now := time.Now()
	start, _, err := quota.Window("daily", now)
	if err != nil {
		t.Fatal(err)
	}
	key := quota.Key{Scope: "user", ScopeID: "alice", QuotaID: "budget", Period: "daily", StartsAt: start}
	r := quota.Record{OwnerUserID: key.ScopeID, Key: key, Measured: quota.Amounts{12, 8, 20}, Charged: quota.Amounts{60, 50, 100}, Alerts: [2]uint64{1 << 63, 1 << 36}}
	if err := s.Save(t.Context(), []quota.Record{r}); err != nil {
		t.Fatal(err)
	}
	l := quota.New(s)
	t.Cleanup(func() {
		if err := l.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	p, err := l.Prepare(t.Context(), []quota.Binding{{Scope: "user", ScopeID: "alice", Quota: resource.Quota{ID: "budget", Period: "daily", Combined: "100", Action: "block_new", Thresholds: []int{63, 64, 100}}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	u := p.Usage()[0]
	if u.Measured.Combined != "20" || u.RecoveryCharge.Combined != "80" || u.Used.Combined != "100" || !u.Exceeded {
		t.Fatalf("incorrect recovery: %+v", u)
	}
	if !slices.Equal(u.Thresholds, []int{63, 64, 100}) {
		t.Fatal("thresholds changed")
	}
}
