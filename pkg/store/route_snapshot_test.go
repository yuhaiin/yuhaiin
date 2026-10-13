package store

import (
	"errors"
	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"testing"
)

func TestRunningReferencesRemainProtectedUntilNewRulesAreApplied(t *testing.T) {
	editor, _, rules := editorStore(t)
	nodes := NewNodeStore(editor.db)
	if err := nodes.Save(t.Context(), contractnode.Node{ID: "node", Name: "Node", Origin: "manual", Enabled: true, Chain: []contractnode.Protocol{{Type: "direct", Direct: &contractnode.Direct{}}}}, 0); err != nil {
		t.Fatal(err)
	}
	resolvers := NewResolverStore(editor.db)
	if err := resolvers.Save(t.Context(), contractresolver.Resolver{ID: "dns", Type: "udp", Host: "127.0.0.1:53"}, 0); err != nil {
		t.Fatal(err)
	}
	inbounds := NewInboundStore(editor.db)
	if err := inbounds.Save(t.Context(), contractinbound.Inbound{ID: "entry", Name: "Entry", Network: contractinbound.NewTypedNetwork(contractinbound.TCPUDPNetwork{Host: "127.0.0.1:9002", UDP: "enabled"}), Protocol: contractinbound.NewTypedProtocol(contractinbound.MixedProtocol{})}, 0); err != nil {
		t.Fatal(err)
	}
	draft, err := editor.Save(t.Context(), contractroute.RuleDraft{Rule: contractroute.RouteRule{ID: "rule", Name: "Rule", Mode: "proxy", Target: contractroute.Target{Type: "node", ID: "node"}, Resolver: "dns", Rules: []contractroute.RuleExpr{{Type: "inbound", Inbound: &contractroute.SourceRef{Names: []string{"entry"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := rules.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := rules.ActivateSnapshot(t.Context(), snapshot.Revision, func() {}); err != nil {
		t.Fatal(err)
	}
	draft.Rule.Mode, draft.Rule.Target, draft.Rule.Resolver = "direct", contractroute.Target{Type: "default"}, ""
	draft.Rule.Rules = []contractroute.RuleExpr{{Type: "always"}}
	if _, err := editor.Save(t.Context(), draft); err != nil {
		t.Fatal(err)
	}
	for _, remove := range []func() error{func() error { return nodes.Delete(t.Context(), "node") }, func() error { return resolvers.Delete(t.Context(), "dns") }, func() error { return inbounds.Delete(t.Context(), "entry") }} {
		if _, ok := errors.AsType[*ResourceInUseError](remove()); !ok {
			t.Fatal("running reference was not protected")
		}
	}
	snapshot, err = rules.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := rules.ActivateSnapshot(t.Context(), snapshot.Revision, func() {}); err != nil {
		t.Fatal(err)
	}
	for _, remove := range []func() error{func() error { return nodes.Delete(t.Context(), "node") }, func() error { return resolvers.Delete(t.Context(), "dns") }, func() error { return inbounds.Delete(t.Context(), "entry") }} {
		if err := remove(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSnapshotsRejectStaleActivationAndKeepImmutableData(t *testing.T) {
	editor, _, rules := editorStore(t)
	draft, err := editor.Save(t.Context(), privateDraft("rule", "Rule"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := rules.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	draft.Lists[0].Source.Local.Lists = []string{"changed.example"}
	if _, err := editor.Save(t.Context(), draft); err != nil {
		t.Fatal(err)
	}
	if before.Lists[0].Source.Local.Lists[0] != "example.com" {
		t.Fatal("snapshot data changed after a save")
	}
	installed := false
	if err := rules.ActivateSnapshot(t.Context(), before.Revision, func() { installed = true }); !errors.Is(err, ErrConflict) || installed {
		t.Fatalf("stale activation: installed=%v err=%v", installed, err)
	}
	current, err := rules.Snapshot(t.Context())
	if err != nil || current.Revision <= before.Revision || current.Lists[0].Source.Local.Lists[0] != "changed.example" {
		t.Fatalf("current snapshot: %+v, %v", current, err)
	}
	if err := rules.ActivateSnapshot(t.Context(), current.Revision, func() { installed = true }); err != nil || !installed {
		t.Fatalf("activation: %v", err)
	}
	var applied uint64
	if err := rules.db.QueryRowContext(t.Context(), `SELECT applied_revision FROM route_configuration_state WHERE id = 1`).Scan(&applied); err != nil || applied != current.Revision {
		t.Fatalf("persisted activation: %d, %v", applied, err)
	}
}

func TestDefaultConfigUsesOptimisticRevisionAndRejectsMissingReferences(t *testing.T) {
	editor, _, _ := editorStore(t)
	settings := NewRouteSettingsStore(editor.db)
	value, err := settings.SaveConfig(t.Context(), contractroute.Config{DefaultMode: "block"})
	if err != nil || value.Revision != 1 || value.DefaultMode != "block" {
		t.Fatalf("save default config: %+v, %v", value, err)
	}
	if _, err := settings.SaveConfig(t.Context(), contractroute.Config{DefaultMode: "direct"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save: %v", err)
	}
	if _, err := settings.SaveConfig(t.Context(), contractroute.Config{Revision: value.Revision, DefaultMode: "proxy", DefaultTarget: contractroute.Target{Type: "node", ID: "missing"}}); err == nil {
		t.Fatal("missing default node accepted")
	}
	got, err := settings.Settings(t.Context())
	if err != nil || got != value {
		t.Fatalf("invalid save changed config: %+v, %v", got, err)
	}
}

func TestSharedListAndSettingsRefreshPreserveConcurrentEdits(t *testing.T) {
	editor, lists, _ := editorStore(t)
	list := contractroute.RouteListDetail{ID: "shared", Name: "Before", Type: "host", Source: contractroute.ListSource{Type: "remote", Remote: &contractroute.RemoteSource{URLs: []string{"https://example.com/list"}}}}
	if err := lists.SaveRouteList(t.Context(), list, 0); err != nil {
		t.Fatal(err)
	}
	downloaded, err := lists.GetRouteList(t.Context(), list.ID)
	if err != nil {
		t.Fatal(err)
	}
	current := downloaded
	current.Name = "Renamed"
	if err := lists.SaveRouteList(t.Context(), current, 0); err != nil {
		t.Fatal(err)
	}
	if err := lists.SaveRouteList(t.Context(), downloaded, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale list save: %v", err)
	}
	downloaded.ErrorMsgs = []string{"download failed"}
	if err := lists.UpdateRefreshErrors(t.Context(), downloaded); err != nil {
		t.Fatal(err)
	}
	current, err = lists.GetRouteList(t.Context(), list.ID)
	if err != nil || current.Name != "Renamed" || len(current.ErrorMsgs) != 1 {
		t.Fatalf("refresh overwrote edit: %+v, %v", current, err)
	}
	current.Source = contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: []string{"new.example"}}}
	if err := lists.SaveRouteList(t.Context(), current, 0); err != nil {
		t.Fatal(err)
	}
	if err := lists.UpdateRefreshErrors(t.Context(), downloaded); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed source accepted old refresh: %v", err)
	}
	settings := NewRouteSettingsStore(editor.db)
	config, err := settings.SaveListConfig(t.Context(), contractroute.ListConfig{HostIndexDisk: false}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.SaveListConfig(t.Context(), contractroute.ListConfig{}, 60); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale settings save: %v", err)
	}
	if err := settings.RecordRefresh(t.Context(), RouteListSettings{LastRefreshTime: 123}); err != nil {
		t.Fatal(err)
	}
	got, err := settings.ListSettings(t.Context())
	if err != nil || got.RefreshInterval != 30 || got.HostIndexDisk || got.Revision != config.Revision || got.LastRefreshTime != 123 {
		t.Fatalf("refresh overwrote settings: %+v, %v", got, err)
	}
}
