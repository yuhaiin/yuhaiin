package route

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type routeConfigurationFixture struct {
	backend *ConfigurationChanges
	rules   *Rules
	router  *Route
	db      *sqlite.Store
	ctx     context.Context
}

func routeConfigurationTest(t *testing.T) *routeConfigurationFixture {
	t.Helper()
	old := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	t.Cleanup(func() { configuration.DataDir.Store(old) })
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	settings := plainstore.NewRouteSettingsStore(db.DB())
	book := plainstore.NewRouteRuleStore(db.DB())
	lists := NewLists(plainstore.NewRouteListStore(db.DB()), settings, t.TempDir())
	t.Cleanup(func() { _ = lists.Close() })
	router := NewRoute(nil, staticResolverBook{resolver: staticResolver{}}, lists, nil)
	rules := NewRules(book, settings, router)
	t.Cleanup(func() { _ = rules.Close() })
	backend := NewConfigurationChanges(db.DB(), NewContractRuleController(rules))
	if err = backend.Enable(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx := configchange.WithActor(t.Context(), configchange.Actor{ID: "operator"})
	ctx = secret.WithCapabilities(ctx, secret.Capabilities{Manage: true})
	return &routeConfigurationFixture{backend: backend, rules: rules, router: router, db: db, ctx: ctx}
}
func configurationJSON(t *testing.T, value any) jsontext.Value {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func (f *routeConfigurationFixture) commit(t *testing.T, c configchange.Change) configchange.Change {
	t.Helper()
	d, err := f.backend.Journal().Payload(f.ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.backend.Journal().Commit(f.ctx, c.ID, func(ctx context.Context) error { return f.backend.Apply(ctx, d, false) })
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestConfigurationDefaultsAtomicActivationAndPersistenceFailure(t *testing.T) {
	f := routeConfigurationTest(t)
	staged, err := f.backend.Stage(f.ctx, "route-defaults", "route-defaults", "save", configurationJSON(t, contractroute.Config{DefaultMode: "block", DefaultTarget: contractroute.Target{Type: "default"}}))
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := netapi.ParseAddressPort("tcp", "unmatched.example", 443)
	if got := f.router.ms.Match(netapi.WithContext(f.ctx), addr); got.Mode() == ModeBlock {
		t.Fatal("staging changed active routing")
	}
	if _, err = f.db.DB().ExecContext(f.ctx, `CREATE TRIGGER break_activation BEFORE UPDATE OF applied_revision ON route_configuration_state BEGIN SELECT RAISE(FAIL,'activation persistence unavailable');END`); err != nil {
		t.Fatal(err)
	}
	d, err := f.backend.Journal().Payload(f.ctx, staged.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.backend.Journal().Commit(f.ctx, staged.ID, func(ctx context.Context) error { return f.backend.Apply(ctx, d, false) }); err == nil {
		t.Fatal("committed without durable activation marker")
	}
	settings, err := f.backend.settings.Settings(f.ctx)
	if err != nil || settings.Revision != 0 || settings.DefaultMode != "proxy" {
		t.Fatalf("partial settings=%+v err=%v", settings, err)
	}
	if got := f.router.ms.Match(netapi.WithContext(f.ctx), addr); got.Mode() == ModeBlock {
		t.Fatal("failed persistence changed runtime")
	}
	entry, err := f.backend.Journal().Get(f.ctx, staged.ID)
	if err != nil || entry.State != "staged" {
		t.Fatalf("partial history=%+v err=%v", entry, err)
	}
	if _, err = f.db.DB().ExecContext(f.ctx, `DROP TRIGGER break_activation`); err != nil {
		t.Fatal(err)
	}
	committed := f.commit(t, staged)
	if active, err := f.backend.Activation(f.ctx, committed); err != nil || active != "active" {
		t.Fatalf("activation=%s err=%v", active, err)
	}
	if got := f.router.ms.Match(netapi.WithContext(f.ctx), addr); got.Mode() != ModeBlock {
		t.Fatal("committed policy was not activated")
	}
	rollback, err := f.backend.Journal().Stage(f.ctx, d.Kind, d.ResourceID, committed.ID, func(ctx context.Context) error { return f.backend.Apply(ctx, d, true) })
	if err != nil {
		t.Fatal(err)
	}
	f.commit(t, rollback)
	if got := f.router.ms.Match(netapi.WithContext(f.ctx), addr); got.Mode() == ModeBlock {
		t.Fatal("rollback did not reactivate prior policy")
	}
}
func TestConfigurationRuleConflictAndConcurrentOrdinaryApply(t *testing.T) {
	f := routeConfigurationTest(t)
	draft, err := f.backend.editor.Save(f.ctx, contractroute.RuleDraft{Rule: contractroute.RouteRule{ID: "rule", Name: "rule", Mode: "direct", Rules: []contractroute.RuleExpr{{Type: "always", Always: &contractroute.MatchAllExpr{}}}}})
	if err != nil {
		t.Fatal(err)
	}
	draft.Rule.Mode = "block"
	staged, err := f.backend.Stage(f.ctx, "route-rule", draft.Rule.ID, "save", configurationJSON(t, draft))
	if err != nil {
		t.Fatal(err)
	}
	concurrent := draft
	concurrent.Rule.Name = "concurrent"
	if _, err = f.backend.editor.Save(f.ctx, concurrent); err != nil {
		t.Fatal(err)
	}
	d, err := f.backend.Journal().Payload(f.ctx, staged.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.backend.Journal().Commit(f.ctx, staged.ID, func(ctx context.Context) error { return f.backend.Apply(ctx, d, false) }); !errors.Is(err, configchange.ErrConflict) {
		t.Fatalf("missed rule conflict: %v", err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	failures := make(chan error, 1)
	wg.Go(func() {
		for range 20 {
			if err := f.rules.Apply(ctx); err != nil {
				select {
				case failures <- err:
				default:
				}
				return
			}
		}
	})
	for range 10 {
		current, err := f.backend.settings.Settings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c, err := f.backend.Stage(ctx, "route-defaults", "route-defaults", "save", configurationJSON(t, contractroute.Config{Revision: current.Revision, DefaultMode: "proxy", DefaultTarget: contractroute.Target{Type: "default"}}))
		if err != nil {
			t.Fatal(err)
		}
		f.commit(t, c)
	}
	wg.Wait()
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}
}
func TestConfigurationRemotePrefetchReleasesDatabaseAndMasksProofs(t *testing.T) {
	f := routeConfigurationTest(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var count int
		if err := f.db.DB().QueryRowContext(r.Context(), `SELECT count(*) FROM route_rules_v2`).Scan(&count); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_, _ = io.WriteString(w, "allowed.example\n")
	}))
	defer server.Close()
	proofURL := strings.Replace(server.URL, "://", "://user:private-password@", 1) + "/private-path?token=private-query"
	list := contractroute.RouteListDetail{ID: "remote", Name: "remote", Type: "host", Source: contractroute.ListSource{Type: "remote", Remote: &contractroute.RemoteSource{URLs: []string{proofURL, server.URL + "/private-path-only"}}}}
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	staged, err := f.backend.Stage(ctx, "route-list", list.ID, "save", configurationJSON(t, list))
	if err != nil {
		t.Fatal(err)
	}
	for _, proof := range []string{"private-password", "private-path", "private-query", "private-path-only"} {
		if strings.Contains(string(staged.Diff), proof) {
			t.Fatal("proof leaked in history")
		}
	}
	f.commit(t, staged)
	stored, err := f.backend.lists.GetRouteList(f.ctx, list.ID)
	if err != nil || stored.Source.Remote.URLs[0] != proofURL {
		t.Fatal("secret source not preserved", err)
	}
	redacted, err := secret.Redact(stored)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(redacted)
	for _, proof := range []string{"private-password", "private-path", "private-query", "private-path-only"} {
		if strings.Contains(string(encoded), proof) {
			t.Fatalf("default read leaked %s", proof)
		}
	}
}
func TestConfigurationRejectsIncompleteCandidateButCanRemoveBrokenRule(t *testing.T) {
	f := routeConfigurationTest(t)
	missing := contractroute.RouteListDetail{ID: "missing", Name: "missing", Type: "host", Source: contractroute.ListSource{Type: "remote", Remote: &contractroute.RemoteSource{URLs: []string{"file://" + filepath.Join(t.TempDir(), "missing")}}}}
	if err := f.backend.lists.SaveRouteList(f.ctx, missing, 0); err != nil {
		t.Fatal(err)
	}
	draft := contractroute.RuleDraft{Rule: contractroute.RouteRule{ID: "broken", Name: "broken", Mode: "block", Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: missing.ID}}}}}
	// Existing legacy save remains available for recovery; the strict workflow
	// refuses to publish a snapshot with skipped/degraded matching conditions.
	saved, err := f.backend.editor.Save(f.ctx, draft)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.backend.Stage(f.ctx, "route-defaults", "route-defaults", "save", configurationJSON(t, contractroute.Config{DefaultMode: "direct", DefaultTarget: contractroute.Target{Type: "default"}})); err == nil {
		t.Fatal("incomplete candidate activated")
	}
	removal, err := f.backend.Stage(f.ctx, "route-rule", saved.Rule.ID, "delete", configurationJSON(t, struct {
		Revision uint64 `json:"revision"`
	}{saved.Rule.Revision}))
	if err != nil {
		t.Fatal(err)
	}
	f.commit(t, removal)
	status, err := f.rules.ActivationStatus(f.ctx)
	if err != nil || len(status.SkippedRules) != 0 || status.AppliedRevision != status.SavedRevision {
		t.Fatalf("recovery status=%+v err=%v", status, err)
	}
}

func TestConfigurationOrderStagesRollbackAndReferenceConflicts(t *testing.T) {
	f := routeConfigurationTest(t)
	for _, id := range []string{"one", "two", "three"} {
		draft := contractroute.RuleDraft{Rule: contractroute.RouteRule{ID: id, Name: id, Mode: "direct", Rules: []contractroute.RuleExpr{{Type: "always", Always: &contractroute.MatchAllExpr{}}}}}
		stage, err := f.backend.Stage(f.ctx, "route-rule", id, "save", configurationJSON(t, draft))
		if err != nil {
			t.Fatal(err)
		}
		f.commit(t, stage)
	}
	order := func() string {
		entries, err := f.backend.rules.Order(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		ids := []string{}
		for _, entry := range entries {
			ids = append(ids, entry.ID)
		}
		return strings.Join(ids, ",")
	}
	stage, err := f.backend.Stage(f.ctx, "route-order", "order", "save", configurationJSON(t, map[string]any{"ids": []string{"three", "one", "two"}}))
	if err != nil {
		t.Fatal(err)
	}
	if order() != "one,two,three" {
		t.Fatal("staged order became active")
	}
	committed := f.commit(t, stage)
	if order() != "three,one,two" {
		t.Fatal("order commit failed")
	}
	d, err := f.backend.journal.Payload(f.ctx, committed.ID)
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := f.backend.journal.Stage(f.ctx, d.Kind, d.ResourceID, committed.ID, func(ctx context.Context) error { return f.backend.Apply(ctx, d, true) })
	if err != nil {
		t.Fatal(err)
	}
	f.commit(t, rollback)
	if order() != "one,two,three" {
		t.Fatal("order rollback failed")
	}
	// Deleting and restoring a rule also restores its position.
	current, err := f.backend.rules.RuleChange(f.ctx, "two")
	if err != nil {
		t.Fatal(err)
	}
	removal, err := f.backend.Stage(f.ctx, "route-rule", "two", "delete", configurationJSON(t, map[string]any{"revision": current.Draft.Rule.Revision}))
	if err != nil {
		t.Fatal(err)
	}
	removed := f.commit(t, removal)
	d, err = f.backend.journal.Payload(f.ctx, removed.ID)
	if err != nil {
		t.Fatal(err)
	}
	restore, err := f.backend.journal.Stage(f.ctx, d.Kind, d.ResourceID, removed.ID, func(ctx context.Context) error { return f.backend.Apply(ctx, d, true) })
	if err != nil {
		t.Fatal(err)
	}
	f.commit(t, restore)
	if order() != "one,two,three" {
		t.Fatal("restored rule lost priority", order())
	}
	// A missing rule cannot be silently dropped during rollback.
	if err = f.backend.rules.DeleteRule(t.Context(), "one"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.backend.journal.Stage(f.ctx, "route-order", "order", committed.ID, func(ctx context.Context) error {
		return f.backend.Apply(ctx, configchange.Document{Kind: "route-order", ResourceID: "order", Before: configurationJSON(t, []plainstore.RouteOrderEntry{{ID: "one"}, {ID: "two"}, {ID: "three"}})}, true)
	}); !errors.Is(err, configchange.ErrConflict) {
		t.Fatal("missing reference rollback accepted", err)
	}
}

func TestConfigurationRevokedSecretAuthorityDoesNotPrefetch(t *testing.T) {
	f := routeConfigurationTest(t)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "example.test\n")
	}))
	defer server.Close()
	value := contractroute.RouteListDetail{ID: "private", Name: "Private", Type: "host", Source: contractroute.ListSource{Type: "remote", Remote: &contractroute.RemoteSource{URLs: []string{server.URL + "/path-proof"}}}}
	staged, err := f.backend.Stage(f.ctx, "route-list", value.ID, "save", configurationJSON(t, value))
	if err != nil {
		t.Fatal(err)
	}
	d, err := f.backend.journal.Payload(f.ctx, staged.ID)
	if err != nil {
		t.Fatal(err)
	}
	before := requests.Load()
	restricted := secret.WithCapabilities(f.ctx, secret.Capabilities{})
	if _, err = f.backend.journal.Commit(restricted, staged.ID, func(ctx context.Context) error { return f.backend.Apply(ctx, d, false) }); !errors.Is(err, secret.ErrManage) {
		t.Fatal("revoked secret manager committed", err)
	}
	if requests.Load() != before {
		t.Fatal("secret URL was requested before authorization")
	}
}
