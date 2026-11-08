package yuhaiin

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/net/defaults"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	"github.com/Asutorufa/yuhaiin/pkg/resolver"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type routeRecorder []netip.Prefix

func (r *routeRecorder) Add(cidr *CIDR) {
	*r = append(*r, netip.PrefixFrom(netip.MustParseAddr(cidr.IP), int(cidr.Mask)))
}

func androidFakeIPRoutes(t *testing.T) []netip.Prefix {
	t.Helper()
	var routes routeRecorder
	if err := AddFakeDnsCidr(&routes); err != nil {
		t.Fatal(err)
	}
	return routes
}

// coreFakeIPRanges builds the resolver exactly as app.Start does and returns
// the pools it actually serves.
func coreFakeIPRanges(t *testing.T) []netip.Prefix {
	t.Helper()
	ctx := t.Context()
	state := migrate.NewStateDB(paths.PathGenerator.State(savepath))
	defer func() { _ = state.Close() }()
	if err := state.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	config, err := plainstore.NewResolverConfigStore(db).FakeDNS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	upstream := netapi.ErrorResolver(func(string) error { return errors.New("unused") })
	fake, err := resolver.NewFakeDNS(nil, upstream, filepath.Join(t.TempDir(), "fakeip.db"), config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fake.Close() }()
	ranges := fake.FakeIPRanges()
	return ranges[:]
}

func withAndroidState(t *testing.T, fn func(*sql.DB)) {
	t.Helper()
	if err := withStateDB(t.Context(), func(db *sql.DB) error {
		fn(db)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func setFakeDNSRanges(t *testing.T, ipv4, ipv6 string) {
	t.Helper()
	withAndroidState(t, func(db *sql.DB) {
		if _, err := db.ExecContext(t.Context(),
			"UPDATE dns_settings SET fakedns_ipv4_range = ?, fakedns_ipv6_range = ? WHERE id = 1", ipv4, ipv6); err != nil {
			t.Fatal(err)
		}
	})
}

func defaultFakeIPRoutes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix(defaults.DefaultFakeIPv4Range),
		netip.MustParsePrefix(defaults.DefaultFakeIPv6Range),
	}
}

func assertRoutes(t *testing.T, got, want []netip.Prefix) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("FakeIP routes = %v, want %v", got, want)
	}
	for _, prefix := range got {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			t.Fatalf("FakeIP route %v is not a valid network prefix", prefix)
		}
	}
	if !got[0].Addr().Is4() || !got[1].Addr().Is6() {
		t.Fatalf("FakeIP routes have the wrong families: %v", got)
	}
}

func TestAddFakeDnsCidrEmptyDatabaseMatchesCoreAcrossStarts(t *testing.T) {
	SetSavePath(t.TempDir())

	// The VPN builder reads the routes before App.Start migrates the database.
	first := androidFakeIPRoutes(t)
	core := coreFakeIPRanges(t)
	assertRoutes(t, first, core)
	// Later initializations must not seed a different random pool.
	assertRoutes(t, androidFakeIPRoutes(t), first)
	assertRoutes(t, coreFakeIPRanges(t), first)

	benchmarkV4 := netip.MustParsePrefix("198.18.0.0/15")
	benchmarkV6 := netip.MustParsePrefix("2001:2::/48")
	if !benchmarkV4.Contains(first[0].Addr()) || !benchmarkV6.Contains(first[1].Addr()) {
		t.Fatalf("seeded FakeIP routes %v are outside the benchmarking ranges", first)
	}
}

func TestAddFakeDnsCidrMissingSettingsRowUsesDefaults(t *testing.T) {
	SetSavePath(t.TempDir())
	withAndroidState(t, func(db *sql.DB) {
		if _, err := db.ExecContext(t.Context(), "DELETE FROM dns_settings"); err != nil {
			t.Fatal(err)
		}
	})

	assertRoutes(t, androidFakeIPRoutes(t), defaultFakeIPRoutes())
	assertRoutes(t, coreFakeIPRanges(t), defaultFakeIPRoutes())
}

func TestAddFakeDnsCidrRanges(t *testing.T) {
	for _, tt := range []struct {
		name       string
		ipv4, ipv6 string
		want       []netip.Prefix
	}{
		{"empty values use defaults", "", "", defaultFakeIPRoutes()},
		{"defaults", defaults.DefaultFakeIPv4Range, defaults.DefaultFakeIPv6Range, defaultFakeIPRoutes()},
		{"custom", "10.42.0.0/16", "fd44:8589:cd09:ffff::/64", []netip.Prefix{
			netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("fd44:8589:cd09:ffff::/64"),
		}},
		{"custom with host bits", "10.42.7.9/16", "fd44:8589:cd09:ffff::1/64", []netip.Prefix{
			netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("fd44:8589:cd09:ffff::/64"),
		}},
		{"malformed", "not-a-cidr", "2001:2::/129", defaultFakeIPRoutes()},
		{"swapped families", "2001:2::/64", "198.18.0.0/16", defaultFakeIPRoutes()},
		{"custom IPv4 invalid IPv6", "10.42.0.0/16", "bad", []netip.Prefix{
			netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix(defaults.DefaultFakeIPv6Range),
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			SetSavePath(t.TempDir())
			androidFakeIPRoutes(t) // initialize like the VPN builder does
			setFakeDNSRanges(t, tt.ipv4, tt.ipv6)

			got := androidFakeIPRoutes(t)
			assertRoutes(t, got, tt.want)
			assertRoutes(t, coreFakeIPRanges(t), got)
		})
	}
}

func TestAddFakeDnsCidrReportsDatabaseErrors(t *testing.T) {
	dir := t.TempDir()
	SetSavePath(dir)
	statePath := paths.PathGenerator.State(dir)
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("this is not a sqlite database, it only looks like one to the opener"), 0o600); err != nil {
		t.Fatal(err)
	}

	var routes routeRecorder
	if err := AddFakeDnsCidr(&routes); err == nil {
		t.Fatal("AddFakeDnsCidr succeeded on an unreadable database")
	}
	if len(routes) != 0 {
		t.Fatalf("routes were added after a database error: %v", routes)
	}
}

func TestAddFakeDnsCidrRequiresSavePath(t *testing.T) {
	old := savepath
	savepath = ""
	t.Cleanup(func() { savepath = old })
	if err := AddFakeDnsCidr(new(routeRecorder)); err == nil {
		t.Fatal("AddFakeDnsCidr succeeded without a configuration path")
	}
}

func TestIsIPv6ReadsMigratedSettings(t *testing.T) {
	SetSavePath(t.TempDir())
	// Fresh installs seed general.ipv6=true.
	if !IsIPv6() {
		t.Fatal("IsIPv6() = false on a fresh database")
	}
	withAndroidState(t, func(db *sql.DB) {
		store := plainstore.NewSettingsStore(db)
		settings, err := store.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		settings.IPv6 = false
		if _, err := store.Save(context.Background(), settings); err != nil {
			t.Fatal(err)
		}
	})
	if IsIPv6() {
		t.Fatal("IsIPv6() = true after disabling IPv6")
	}
}
