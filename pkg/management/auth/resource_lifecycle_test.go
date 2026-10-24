package auth

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

func TestResourcePreparationDoesNotBlockUnchangedAuthentication(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	alice, bob := testUser(t, s, "alice", NoManagement), testUser(t, s, "bob", NoManagement)
	p, err := NewProxyCredentials(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ac, err := p.Issue(t.Context(), principal(alice), ProxyCredentialRequest{Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	bc, err := p.Issue(t.Context(), principal(bob), ProxyCredentialRequest{Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	verify := p.Verifier("entry", "http", []string{alice.ID, bob.ID})
	prior, err := verify(t.Context(), alice.Login, []byte(ac.Secret))
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	if err := p.SetResourceObserver(func(bindings []trafficcontrol.IdentityBinding) error {
		for _, binding := range bindings {
			if binding.UserID == alice.ID && len(binding.GroupIDs) > 0 {
				close(entered)
				<-release
				break
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveGroup(t.Context(), principal(admin), "", GroupRequest{Name: "updated", Members: []string{alice.ID}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.Reload() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("observer not reached")
	}
	read := make(chan error, 1)
	go func() { _, err := verify(t.Context(), bob.Login, []byte(bc.Secret)); read <- err }()
	select {
	case err := <-read:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("resource preparation blocked unrelated authentication")
	}
	if prior.Valid() {
		t.Fatal("changed identity remained valid during preparation")
	}
	if _, err := verify(t.Context(), alice.Login, []byte(ac.Secret)); err == nil {
		t.Fatal("changed membership published before resources")
	}
	once.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t.Context(), alice.Login, []byte(ac.Secret)); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteQuotaCleanShutdownReturnsUnusedCredit(t *testing.T) {
	s := testStore(t)
	store := quotaStore{db: s.db}
	ledger := quota.New(store)
	binding := quota.Binding{Scope: "user", ScopeID: "alice", Quota: resource.Quota{ID: "life", Period: "lifetime", Combined: "1000", Action: "terminate"}}
	plan, err := ledger.Prepare(t.Context(), []quota.Binding{binding}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var ticket quota.Reservation
	for {
		n, ready, err := plan.TryReserve(time.Now(), quota.Upload, 123, true, &ticket)
		if errors.Is(err, quota.ErrFunding) {
			select {
			case <-ready:
			case <-t.Context().Done():
				t.Fatal("funding canceled")
			}
			continue
		}
		if err != nil || n != 123 {
			t.Fatalf("reservation %d %v", n, err)
		}
		break
	}
	ticket.Commit(123)
	if err := ledger.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	restarted := quota.New(store)
	defer restarted.Close(context.Background())
	next, err := restarted.Prepare(t.Context(), []quota.Binding{binding}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if u := next.Usage()[0]; u.Used.Combined != "123" || u.RecoveryCharge.Combined != "0" {
		t.Fatalf("SQLite clean restart lost credit: %+v", u)
	}
}

func TestQuotaAlertsRetryDurablyWithoutDuplicatingThresholds(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	alice := testUser(t, s, "alice", NoManagement)
	r, p := resourceService(t, s)
	credential, err := p.Issue(t.Context(), principal(alice), ProxyCredentialRequest{Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	config := resource.Config{Enabled: true, DefaultUser: resource.Policy{Quotas: []resource.Quota{{ID: "day", Period: "daily", Combined: "100", Action: "warn", Thresholds: []int{80, 90, 100}}}}}
	if _, err := r.Save(t.Context(), principal(admin), config); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(t.Context(), `CREATE TRIGGER fail_quota_alert BEFORE INSERT ON quota_alerts BEGIN SELECT RAISE(ABORT,'alert storage unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	policy := r.Control.ResolveIdentity("entry", "", alice.ID, credential.ID)
	if n, err := (trafficcontrol.ShapedWriter{Writer: io.Discard, Context: t.Context(), Policy: policy, Direction: trafficcontrol.Upload}).Write(make([]byte, 110)); n != 110 || err != nil {
		t.Fatalf("warn-only write: %d %v", n, err)
	}
	until := time.Now().Add(5 * time.Second)
	for r.alertFailures.Load() == 0 {
		if time.Now().After(until) {
			t.Fatal("alert failure was not observed")
		}
		time.Sleep(time.Millisecond)
	}
	if r.Status().PendingAlerts != 3 {
		t.Fatal("failed alert batch was discarded")
	}
	if _, err := s.db.ExecContext(t.Context(), `DROP TRIGGER fail_quota_alert`); err != nil {
		t.Fatal(err)
	}
	for {
		page, err := r.Alerts(t.Context(), alice.ID, "", 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) == 3 {
			break
		}
		if time.Now().After(until) {
			t.Fatalf("alerts did not recover: %+v", page)
		}
		time.Sleep(time.Millisecond)
	}
	if n, err := (trafficcontrol.ShapedWriter{Writer: io.Discard, Context: t.Context(), Policy: policy, Direction: trafficcontrol.Upload}).Write([]byte{1}); n != 1 || err != nil {
		t.Fatal(err)
	}
	if page, err := r.Alerts(t.Context(), alice.ID, "", 50); err != nil || len(page.Items) != 3 {
		t.Fatal("threshold alert repeated for each packet", err)
	}
}
