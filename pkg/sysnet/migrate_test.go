package sysnet

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
)

func legacyTun(id string, tun contractinbound.TunProtocol) contractinbound.Inbound {
	return contractinbound.Inbound{ID: id, Name: "TUN " + id, Enabled: true, Protocol: contractinbound.NewTypedProtocol(tun)}
}

func noFiles(path string) ([]byte, error) { return nil, os.ErrNotExist }

func onlyRule(t *testing.T, c sysnet.Config) sysnet.RouteRule {
	t.Helper()
	if len(c.Routes) != 1 {
		t.Fatalf("rules = %+v", c.Routes)
	}
	return c.Routes[0]
}

func TestMigrateRoutingModes(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for name, routing := range map[string]contractinbound.TunRouting{
		"global":      {Mode: "global", BypassCIDRs: []string{"192.168.1.0/24"}},
		"non_private": {Mode: "non_private", IncludeCIDRs: []string{"10.8.0.0/16"}, BypassCIDRs: []string{"203.0.113.0/24"}},
		"custom":      {Mode: "custom", IncludeCIDRs: []string{"8.8.8.8/32"}, GeoIPCountries: []string{"JP", "US"}, GeoIPInvert: true},
	} {
		t.Run(name, func(t *testing.T) {
			in := legacyTun("tun", contractinbound.TunProtocol{Routing: routing, Routes: []string{"1.1.1.1"}})
			config, cleared := MigrateLegacy(sysnet.Config{}, []contractinbound.Inbound{in}, "darwin", noFiles, now)
			r := onlyRule(t, config)
			if r.Match.Mode != routing.Mode || !slices.Equal(r.Match.IncludeCIDRs, routing.IncludeCIDRs) || !slices.Equal(r.Match.BypassCIDRs, routing.BypassCIDRs) ||
				!slices.Equal(r.Match.GeoIPCountries, routing.GeoIPCountries) || r.Match.GeoIPInvert != routing.GeoIPInvert {
				t.Fatalf("match = %+v", r.Match)
			}
			if r.Target != (sysnet.RouteTarget{Type: sysnet.TargetTunInbound, InboundID: "tun"}) || !r.Enabled || !strings.HasPrefix(r.ID, "legacy-tun-tun-") {
				t.Fatalf("rule = %+v", r)
			}
			if !slices.Equal(cleared, []string{"tun"}) || len(config.Migrations) != 1 || config.Migrations[0].RuleID != r.ID ||
				config.Migrations[0].Source != "tun_routing:"+routing.Mode || len(config.Migrations[0].Warnings) != 1 {
				t.Fatalf("migration = %+v cleared %v", config.Migrations, cleared)
			}
			if err := config.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMigrateLegacyListsPreservesPlatformBehavior(t *testing.T) {
	files := func(path string) ([]byte, error) {
		if path == "/etc/yuhaiin/routes.txt" {
			return []byte("192.0.2.0/24\nnot-a-route\n\n2001:db8::/32\n"), nil
		}
		return nil, errors.New("permission denied")
	}
	in := legacyTun("tun", contractinbound.TunProtocol{Routes: []string{"198.18.0.0/15", "8.8.8.8", "file:/etc/yuhaiin/routes.txt", "file:/missing", "bad"},
		Excludes: []string{"10.0.0.0/8"}})

	// Desktop installed routes and excludes alike.
	config, cleared := MigrateLegacy(sysnet.Config{}, []contractinbound.Inbound{in}, "linux", files, time.Now())
	r := onlyRule(t, config)
	want := []string{"10.0.0.0/8", "192.0.2.0/24", "198.18.0.0/15", "2001:db8::/32", "8.8.8.8/32"}
	if r.Match.Mode != sysnet.ModeCustom || !slices.Equal(r.Match.IncludeCIDRs, want) || len(r.Match.BypassCIDRs) != 0 || len(cleared) != 1 {
		t.Fatalf("desktop match = %+v", r.Match)
	}
	warnings := strings.Join(config.Migrations[0].Warnings, "\n")
	for _, w := range []string{"kept as routes", `"not-a-route"`, `"bad"`, "/missing", "copied"} {
		if !strings.Contains(warnings, w) {
			t.Errorf("missing warning %q in %s", w, warnings)
		}
	}

	// Android excluded the excludes.
	config, _ = MigrateLegacy(sysnet.Config{}, []contractinbound.Inbound{in}, "android", files, time.Now())
	r = onlyRule(t, config)
	if !slices.Equal(r.Match.BypassCIDRs, []string{"10.0.0.0/8"}) || slices.Contains(r.Match.IncludeCIDRs, "10.0.0.0/8") {
		t.Fatalf("android match = %+v", r.Match)
	}
	// Android without routes used its route profile: nothing to migrate.
	onlyExcludes := legacyTun("tun", contractinbound.TunProtocol{Excludes: []string{"10.0.0.0/8"}})
	config, cleared = MigrateLegacy(sysnet.Config{}, []contractinbound.Inbound{onlyExcludes}, "android", files, time.Now())
	if len(config.Routes) != 0 || !slices.Equal(cleared, []string{"tun"}) || len(config.Migrations) != 1 || len(config.Migrations[0].Warnings) != 1 {
		t.Fatalf("android profile config = %+v", config)
	}
}

func TestMigrateIsIdempotentAndKeepsConflicts(t *testing.T) {
	existing := sysnet.Config{Routes: []sysnet.RouteRule{rule("mine", 2000, custom("9.9.9.9"), ifTarget("wg0"))}}
	inbounds := []contractinbound.Inbound{
		legacyTun("b", contractinbound.TunProtocol{Routing: contractinbound.TunRouting{Mode: "global"}}),
		legacyTun("a", contractinbound.TunProtocol{Routing: contractinbound.TunRouting{Mode: "global"}}),
		{ID: "http", Protocol: contractinbound.NewTypedProtocol(contractinbound.HTTPProtocol{})},
		legacyTun("clean", contractinbound.TunProtocol{}),
	}
	first, cleared := MigrateLegacy(existing, inbounds, "linux", noFiles, time.Now())
	if len(first.Routes) != 3 || !slices.Equal(cleared, []string{"a", "b"}) {
		t.Fatalf("first migration = %+v cleared %v", first.Routes, cleared)
	}
	// Both TUNs keep their overlapping Global rules, in inbound order, after
	// existing rules; the status shows which one wins.
	if first.Routes[1].Target.InboundID != "a" || first.Routes[2].Target.InboundID != "b" || first.Routes[1].Priority <= 2000 || first.Routes[2].Priority <= first.Routes[1].Priority {
		t.Fatalf("order = %+v", first.Routes)
	}
	// Running again (crash before clearing, or a restored old backup) adds nothing.
	second, _ := MigrateLegacy(first, inbounds, "linux", noFiles, time.Now())
	if len(second.Routes) != 3 || len(second.Migrations) != 2 {
		t.Fatalf("repeated migration = %d rules, %d records", len(second.Routes), len(second.Migrations))
	}
	// Cleared inbounds are not migrated again.
	clearedInbounds := []contractinbound.Inbound{ClearLegacyRouting(inbounds[0]), ClearLegacyRouting(inbounds[1])}
	if HasLegacyRouting(clearedInbounds[0]) {
		t.Fatal("cleared inbound still has legacy routing")
	}
	third, none := MigrateLegacy(second, clearedInbounds, "linux", noFiles, time.Now())
	if len(none) != 0 || len(third.Routes) != 3 {
		t.Fatal("cleared inbounds migrated again")
	}
}

func TestManagerMigrationPersistsBeforeClearing(t *testing.T) {
	n := newTestNet(t, sysnet.Config{})
	store := &memoryStore{}
	if err := n.m.SetStore(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	in := legacyTun("tun", contractinbound.TunProtocol{Routing: contractinbound.TunRouting{Mode: "non_private"}})
	cleared, err := n.m.MigrateLegacyTun(t.Context(), []contractinbound.Inbound{in}, noFiles)
	if err != nil || !slices.Equal(cleared, []string{"tun"}) {
		t.Fatalf("cleared = %v, %v", cleared, err)
	}
	if len(store.config.Routes) != 1 || len(store.config.Migrations) != 1 {
		t.Fatalf("not persisted: %+v", store.config)
	}
	// Migration records survive API saves, which cannot change them.
	if _, err := n.m.Save(t.Context(), sysnet.Config{Routes: store.config.Routes}); err != nil {
		t.Fatal(err)
	}
	if s := n.m.Status(); len(s.Migrations) != 1 || s.Migrations[0].InboundID != "tun" {
		t.Fatalf("migration status = %+v", s.Migrations)
	}
	if st := ruleStatus(t, n.m.Status(), store.config.Routes[0].ID); st.State != sysnet.StateUnavailable {
		t.Fatalf("migrated rule before the TUN starts = %+v", st)
	}
}
