package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

func TestQuotaAlertRetentionAndHistoricalCredentialOwner(t *testing.T) {
	s := testStore(t)
	alice, bob := testUser(t, s, "alice", NoManagement), testUser(t, s, "bob", NoManagement)
	p, err := NewProxyCredentials(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	credential, err := p.Issue(t.Context(), principal(alice), ProxyCredentialRequest{Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	l := quota.New(quotaStore{db: s.db})
	defer l.Close(context.Background())
	r := &ResourcePolicies{store: s, Ledger: l}
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(t.Context(), `INSERT INTO quota_alerts(owner_user_id,scope,scope_id,quota_id,period,starts_at,occurred_at,threshold) VALUES(?,'credential',?,?,'daily',0,1,80)`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	for i := range quotaAlertRetention + 5 {
		if _, err := stmt.ExecContext(t.Context(), alice.ID, credential.ID, fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(t.Context(), `DELETE FROM proxy_credentials WHERE id=?`, credential.ID); err != nil {
		t.Fatal(err)
	}
	r.pendingAlerts = []quota.Event{{OwnerUserID: alice.ID, Key: quota.Key{Scope: "credential", ScopeID: credential.ID, QuotaID: "latest", Period: "daily"}, At: time.Now().Unix(), Threshold: 100}}
	if err := r.flushQuotaAlerts(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count, oldest int
	if err := s.db.QueryRowContext(t.Context(), `SELECT count(*),min(id) FROM quota_alerts`).Scan(&count, &oldest); err != nil || count != quotaAlertRetention || oldest != 7 {
		t.Fatalf("unbounded alert history: count=%d oldest=%d err=%v", count, oldest, err)
	}
	page, err := r.Alerts(t.Context(), alice.ID, "", 1)
	if err != nil || len(page.Items) != 1 || page.Items[0].ScopeID != credential.ID || page.Items[0].QuotaID != "latest" {
		t.Fatalf("deleted credential lost its historical owner: %+v %v", page, err)
	}
	if page, err := r.Alerts(t.Context(), bob.ID, "", 50); err != nil || len(page.Items) != 0 {
		t.Fatal("historical credential alerts crossed owner boundary", err)
	}
}
