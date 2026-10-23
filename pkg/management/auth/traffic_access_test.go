package auth

import (
	"errors"
	"sync"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	rule "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

func TestAccessPolicyPersistenceReferencesAndAtomicActivation(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	group, err := s.SaveGroup(t.Context(), principal(admin), "", GroupRequest{Name: "Finance", Members: []string{admin.ID}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAccessPolicies(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Controller.Close()
	cfg := contract.Config{Enabled: true, Scope: contract.Scope{AllInbounds: true}, DefaultAction: "deny", Rules: []contract.Rule{{ID: "finance", Action: "allow", Conditions: []rule.RuleExpr{{Type: "group", Group: &rule.IdentityExpr{IDs: []string{group.ID}}}}}}}
	if _, err := a.Save(t.Context(), Principal{}, cfg); !errors.Is(err, ErrForbidden) {
		t.Fatal("unauthorized save", err)
	}
	if v := a.Validate(t.Context(), cfg); !v.Valid {
		t.Fatal(v)
	}
	saved, err := a.Save(t.Context(), principal(admin), cfg)
	if err != nil || saved.Revision != 1 {
		t.Fatalf("save=%+v %v", saved, err)
	}
	if _, err := a.Save(t.Context(), principal(admin), cfg); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision", err)
	}
	if err := s.DeleteGroup(t.Context(), principal(admin), group.ID, group.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("dangling active reference", err)
	}
	restarted, err := NewAccessPolicies(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Controller.Close()
	if got := restarted.Controller.Config(); got.Revision != 1 || !got.Enabled || len(got.Rules) != 1 {
		t.Fatalf("restart lost authorization: %+v", got)
	}
	invalid := saved
	invalid.Rules = []contract.Rule{{ID: "unknown", Action: "allow", Conditions: []rule.RuleExpr{{Type: "group", Group: &rule.IdentityExpr{IDs: []string{"missing"}}}}}}
	if v := a.Validate(t.Context(), invalid); v.Valid {
		t.Fatal("unknown group passed validation")
	}
	if _, err := a.Save(t.Context(), principal(admin), invalid); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown reference", err)
	}
	if a.Controller.Config().Revision != 1 {
		t.Fatal("invalid draft activated")
	}
	if _, err := s.db.ExecContext(t.Context(), `CREATE TRIGGER fail_access_audit BEFORE INSERT ON management_security_events WHEN NEW.event='traffic_access.updated' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	next := saved
	next.Enabled = false
	if _, err := a.Save(t.Context(), principal(admin), next); err == nil {
		t.Fatal("unaudited policy change committed")
	}
	if a.Controller.Config().Revision != 1 || !a.Controller.Config().Enabled {
		t.Fatal("failed audit weakened active authorization")
	}
	var revision int
	if err := s.db.QueryRowContext(t.Context(), `SELECT revision FROM traffic_access_config`).Scan(&revision); err != nil || revision != 1 {
		t.Fatal("failed audit persisted", revision, err)
	}
	if _, err := s.db.ExecContext(t.Context(), `DROP TRIGGER fail_access_audit`); err != nil {
		t.Fatal(err)
	}
	next.Rules = nil
	if _, err := a.Save(t.Context(), principal(admin), next); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(t.Context(), principal(admin), group.ID, group.Revision); err != nil {
		t.Fatal("removed reference retained", err)
	}
}

func TestAccessPolicyConcurrentWritersHaveOneWinner(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	a, err := NewAccessPolicies(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Controller.Close()
	cfg := a.Controller.Config()
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for range 16 {
		wg.Go(func() { _, err := a.Save(t.Context(), principal(admin), cfg); results <- err })
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if winners != 1 || a.Controller.Config().Revision != 1 {
		t.Fatalf("winners=%d config=%+v", winners, a.Controller.Config())
	}
}
