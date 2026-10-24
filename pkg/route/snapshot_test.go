package route

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type changingSnapshotBook struct {
	*plainstore.RouteRuleStore
	change func() error
}

func (s *changingSnapshotBook) ActivateSnapshot(ctx context.Context, revision uint64, install func()) error {
	if s.change != nil {
		change := s.change
		s.change = nil
		if err := change(); err != nil {
			return err
		}
	}
	return s.RouteRuleStore.ActivateSnapshot(ctx, revision, install)
}

func TestSnapshotApplyRetriesConcurrentEditsAndRetainsStateOnFailure(t *testing.T) {
	oldDir := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	t.Cleanup(func() { configuration.DataDir.Store(oldDir) })
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	settings := plainstore.NewRouteSettingsStore(db.DB())
	book := &changingSnapshotBook{RouteRuleStore: plainstore.NewRouteRuleStore(db.DB())}
	lists := NewLists(plainstore.NewRouteListStore(db.DB()), settings, t.TempDir())
	t.Cleanup(func() { _ = lists.Close() })
	router := NewRoute(nil, staticResolverBook{resolver: staticResolver{}}, lists, nil)
	rules := NewRules(book, settings, router)
	t.Cleanup(func() { _ = rules.Close() })
	editor := plainstore.NewRouteEditorStore(db.DB())
	draft, err := editor.Save(t.Context(), contractroute.RuleDraft{
		Rule:  contractroute.RouteRule{ID: "rule", Name: "Websites", Mode: "direct", Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: "sites"}}}},
		Lists: []contractroute.RouteListDetail{{ID: "sites", Name: "Sites", Type: "host", Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: []string{"old.example"}}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	book.change = func() error {
		draft.Lists[0].Source.Local.Lists = []string{"new.example"}
		var err error
		draft, err = editor.Save(t.Context(), draft)
		return err
	}
	if err := rules.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, err := rules.ActivationStatus(t.Context())
	if err != nil || status.AppliedRevision != status.SavedRevision {
		t.Fatalf("versions: %+v, %v", status, err)
	}
	addr, _ := netapi.ParseAddressPort("tcp", "new.example", 443)
	if got := router.ms.Match(netapi.WithContext(t.Context()), addr); got.Mode() != ModeDirect {
		t.Fatalf("concurrent edit was not applied: %s", got.Mode())
	}
	index := lists.hostTrie
	draft.Rule.Mode = "block"
	draft, err = editor.Save(t.Context(), draft)
	if err != nil {
		t.Fatal(err)
	}
	if err := rules.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	if lists.hostTrie != index {
		t.Fatal("action-only edit rebuilt index")
	}
	if _, err := settings.SaveListConfig(t.Context(), contractroute.ListConfig{HostIndexDisk: false}, 0); err != nil {
		t.Fatal(err)
	}
	if lists.hostTrie != index || lists.hostTrie.cache == nil {
		t.Fatal("saving storage settings changed the running index before apply")
	}
	if err := rules.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	if lists.hostTrie.cache != nil {
		t.Fatal("storage setting was not applied with the snapshot")
	}
	index = lists.hostTrie
	invalidGeo := filepath.Join(t.TempDir(), "invalid.mmdb")
	if err := os.WriteFile(invalidGeo, []byte("invalid GeoIP data"), 0o600); err != nil {
		t.Fatal(err)
	}
	geoConfig, err := settings.SaveListConfig(t.Context(), contractroute.ListConfig{Revision: 1, HostIndexDisk: false, MaxMindDBGeoIP: contractroute.MaxMindDBGeoIP{DownloadURL: (&url.URL{Scheme: "file", Path: invalidGeo}).String()}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := rules.Apply(t.Context()); err == nil {
		t.Fatal("invalid GeoIP data was applied")
	}
	if lists.hostTrie != index || lists.LoadGeoip() != nil {
		t.Fatal("invalid GeoIP changed the running matcher")
	}
	if _, err := settings.SaveListConfig(t.Context(), contractroute.ListConfig{Revision: geoConfig.Revision, HostIndexDisk: false}, 0); err != nil {
		t.Fatal(err)
	}
	if err := rules.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	before, _ := rules.ActivationStatus(t.Context())
	var available atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available.Load() {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "recovered.example\n")
	}))
	defer server.Close()
	remote := contractroute.RouteListDetail{
		ID: "remote", Name: "Remote", Type: "host",
		Source: contractroute.ListSource{Type: "remote", Remote: &contractroute.RemoteSource{URLs: []string{strings.Replace(server.URL, "://", "://user:private-password@", 1) + "/private-route-proof?token=private-query-proof"}}},
	}
	if err := plainstore.NewRouteListStore(db.DB()).SaveRouteList(t.Context(), remote, 0); err != nil {
		t.Fatal(err)
	}
	draft.Rule.Rules[0].Host.List = remote.ID
	draft.Lists = nil
	if _, err := editor.Save(t.Context(), draft); err != nil {
		t.Fatal(err)
	}
	if _, err := editor.Save(t.Context(), contractroute.RuleDraft{
		Rule: contractroute.RouteRule{ID: "independent", Name: "Independent", Mode: "direct",
			Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: "working"}}}},
		Lists: []contractroute.RouteListDetail{{ID: "working", Name: "Working", Type: "host",
			Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: []string{"working.example"}}}}},
	}); err != nil {
		t.Fatal(err)
	}
	// One 404 should not block activation of another rule or the saved config.
	if err := rules.Apply(t.Context()); err != nil {
		t.Fatalf("unavailable remote source prevented snapshot activation: %v", err)
	}
	after, _ := rules.ActivationStatus(t.Context())
	if after.AppliedRevision != after.SavedRevision || after.SavedRevision <= before.SavedRevision || after.Error != "" {
		t.Fatalf("list 404 blocked the saved revision: %+v", after)
	}
	if len(after.ListIssues) != 1 || !after.ListIssues[0].Unavailable || len(after.SkippedRules) != 1 ||
		after.SkippedRules[0].ID != draft.Rule.ID {
		t.Fatalf("missing failure diagnostics: %+v", after)
	}
	for _, proof := range []string{"private-password", "private-route-proof", "private-query-proof"} {
		if strings.Contains(after.ListIssues[0].Error, proof) {
			t.Fatalf("runtime status leaked URL proof: %s", after.ListIssues[0].Error)
		}
	}
	working, _ := netapi.ParseAddressPort("tcp", "working.example", 443)
	if got := router.ms.Match(netapi.WithContext(t.Context()), working); got.Mode() != ModeDirect {
		t.Fatalf("unrelated rule was not applied: %s", got.Mode())
	}
	// When the remote source recovers, retrying application re-enables the rule.
	available.Store(true)
	if err := rules.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	recovered, _ := rules.ActivationStatus(t.Context())
	if len(recovered.ListIssues) != 0 || len(recovered.SkippedRules) != 0 {
		t.Fatalf("recovered list still marked unavailable: %+v", recovered)
	}
	recoveredAddr, _ := netapi.ParseAddressPort("tcp", "recovered.example", 443)
	if got := router.ms.Match(netapi.WithContext(t.Context()), recoveredAddr); got.Mode() != ModeBlock {
		t.Fatalf("recovered remote list not enabled: %s", got.Mode())
	}
}

func TestUnmatchedTrafficUsesConfiguredDefaultAction(t *testing.T) {
	matchers := newTestMatchers(t)
	config := &RouteConfig{DefaultMode: "block", DefaultTarget: contractroute.Target{Type: "default"}, DirectResolver: "old"}
	snapshot := plainstore.RouteSnapshot{Revision: 1}
	activate := func(_ context.Context, _ uint64, install func()) error { install(); return nil }
	if err := matchers.UpdateSnapshot(t.Context(), snapshot, activate, config, func() {}); err != nil {
		t.Fatal(err)
	}
	addr, _ := netapi.ParseAddressPort("tcp", "unmatched.example", 443)
	mode := matchers.Match(netapi.WithContext(t.Context()), addr)
	if mode.Mode() != ModeBlock || mode.config != config {
		t.Fatalf("default result: %+v", mode)
	}
	newConfig := &RouteConfig{DefaultMode: "direct", DefaultTarget: contractroute.Target{Type: "default"}}
	if err := matchers.UpdateSnapshot(t.Context(), snapshot, activate, newConfig, func() {}); err != nil {
		t.Fatal(err)
	}
	if mode.config.DirectResolver != "old" {
		t.Fatal("a matched flow lost its configuration snapshot")
	}
}
