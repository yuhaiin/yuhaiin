package route

import (
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestGeoIPCountriesFollowAppliedSnapshot(t *testing.T) {
	oldDir := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	t.Cleanup(func() { configuration.DataDir.Store(oldDir) })
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	settings := plainstore.NewRouteSettingsStore(db.DB())
	lists := NewLists(plainstore.NewRouteListStore(db.DB()), settings, t.TempDir())
	t.Cleanup(func() { _ = lists.Close() })
	router := NewRoute(nil, staticResolverBook{resolver: staticResolver{}}, lists, nil)
	rules := NewRules(plainstore.NewRouteRuleStore(db.DB()), settings, router)
	t.Cleanup(func() { _ = rules.Close() })
	controller := NewContractListController(lists)
	unloaded, err := controller.GeoIPCountries(t.Context())
	if err != nil || unloaded.Loaded || len(unloaded.Codes) != 0 {
		t.Fatalf("unloaded = %+v, %v", unloaded, err)
	}
	var revision uint64
	save := func(path string) {
		t.Helper()
		file, err := filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		config, err := settings.SaveListConfig(t.Context(), contractroute.ListConfig{Revision: revision, MaxMindDBGeoIP: contractroute.MaxMindDBGeoIP{DownloadURL: (&url.URL{Scheme: "file", Path: file}).String()}}, 0)
		if err != nil {
			t.Fatal(err)
		}
		revision = config.Revision
	}
	check := func(want []string) {
		t.Helper()
		got, err := controller.GeoIPCountries(t.Context())
		if err != nil || !got.Loaded || !slices.Equal(got.Codes, want) {
			t.Fatalf("countries = %+v, %v; want %v", got, err, want)
		}
	}
	save("../net/trie/maxminddb/testdata/countries.mmdb")
	if err := rules.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	check([]string{"CN", "JP", "LAN"})
	bad := filepath.Join(t.TempDir(), "invalid.mmdb")
	if err := os.WriteFile(bad, []byte("invalid GeoIP data"), 0o600); err != nil {
		t.Fatal(err)
	}
	save(bad)
	if err := rules.Apply(t.Context()); err == nil {
		t.Fatal("invalid GeoIP data applied")
	}
	check([]string{"CN", "JP", "LAN"})
	save("../net/trie/maxminddb/testdata/updated.mmdb")
	// Saving new configuration does not expose countries until it has applied.
	check([]string{"CN", "JP", "LAN"})
	if err := rules.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	check([]string{"US"})
}
