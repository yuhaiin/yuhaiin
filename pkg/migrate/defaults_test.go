package migrate

import (
	"net/netip"
	"path/filepath"
	"testing"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestFreshSQLiteHasUsableDefaults(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "state.db")
	// Android preferences may bootstrap the SQLite schema before the core.
	precreated, err := storagesqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := precreated.Close(); err != nil {
		t.Fatal(err)
	}
	state := NewStateDB(path)
	defer func() { _ = state.Close() }()
	if err := state.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatal(err)
	}

	inbounds, err := plainstore.NewInboundStore(db).List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(inbounds) != 3 || inbounds[0].ID != "mixed" || !inbounds[0].Enabled ||
		inbounds[0].Protocol.Type != contractinbound.ProtocolMixed ||
		inbounds[0].Network.TCPUDP == nil || inbounds[0].Network.TCPUDP.Host != "127.0.0.1:1080" {
		t.Fatalf("incorrect default mixed inbound: %+v", inbounds)
	}

	if inbounds[1].ID != "tun" || inbounds[1].Enabled ||
		inbounds[1].Protocol.Type != contractinbound.ProtocolTun ||
		inbounds[2].ID != "yuubinsya" || inbounds[2].Enabled ||
		inbounds[2].Protocol.Type != contractinbound.ProtocolYuubinsya {
		t.Fatalf("incorrect disabled inbound presets: %+v", inbounds)
	}

	settings, err := plainstore.NewSettingsStore(db).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !settings.IPv6 || !settings.UseDefaultInterface || !settings.SystemProxy.HTTP {
		t.Fatalf("incorrect default settings: %+v", settings)
	}
	resolvers, err := plainstore.NewResolverStore(db).List(ctx)
	if err != nil || len(resolvers) != 1 || resolvers[0].ID != "bootstrap" {
		t.Fatalf("incorrect bootstrap resolver: %+v, %v", resolvers, err)
	}
	fakedns, err := plainstore.NewResolverConfigStore(db).FakeDNS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := netip.ParsePrefix(fakedns.IPv4Range); err != nil {
		t.Fatalf("invalid default IPv4 FakeDNS range: %v", err)
	}
	if _, err := netip.ParsePrefix(fakedns.IPv6Range); err != nil {
		t.Fatalf("invalid default IPv6 FakeDNS range: %v", err)
	}

	lists, err := plainstore.NewRouteListStore(db).ListRouteListDetails(ctx)
	if err != nil || len(lists) != 1 || lists[0].ID != "LAN" {
		t.Fatalf("default route lists: %+v, %v", lists, err)
	}
	rules, err := plainstore.NewRouteRuleStore(db).ListRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].Rule.ID != "LAN" || rules[0].Rule.Mode != "direct" {
		t.Fatalf("default route rules: %+v, %v", rules, err)
	}
}

func TestSQLiteDefaultsNeverReappearAfterUserDeletesInbound(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "state.db")
	state := NewStateDB(path)
	if err := state.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM inbounds_v2 WHERE id = 'mixed'"); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	restarted := NewStateDB(path)
	defer func() { _ = restarted.Close() }()
	if err := restarted.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db, err = restarted.SQLDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM inbounds_v2 WHERE id = 'mixed'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("default inbound reappeared after deletion: %d", count)
	}
}

func TestSQLiteDefaultsDoNotOverwriteMigratedEmptyDatabase(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := storagesqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx,
		"INSERT INTO metadata(key, value) VALUES ('plain_model_migration_done','1')"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	state := NewStateDB(path)
	defer func() { _ = state.Close() }()
	if err := state.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM inbounds_v2").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("unexpected default inbound in migrated database: %d", count)
	}
}
