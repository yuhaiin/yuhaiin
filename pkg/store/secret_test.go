package store

import (
	"errors"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"path/filepath"
	"testing"
)

func TestProtectedRouteSourcesPreserveSecretsInsideWriteTransaction(t *testing.T) {
	db, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := secret.WithCapabilities(t.Context(), secret.Capabilities{})
	registries := NewRouteRegistryStore(db.DB())
	original, err := registries.SaveRegistry(t.Context(), contractroute.Registry{ID: "private", Name: "Registry", URL: "https://user:private-password@example.test/manifest?key=private-query", Enabled: true}, 123)
	if err != nil {
		t.Fatal(err)
	}
	masked, err := secret.Redact(original)
	if err != nil {
		t.Fatal(err)
	}
	masked.Name = "Renamed"
	got, err := registries.SaveRegistry(ctx, masked, 124)
	if err != nil || got.URL != original.URL {
		t.Fatal("registry edit lost secret URL", err)
	}
	masked.URL = "https://example.test/new?key=new-proof"
	if _, err := registries.SaveRegistry(ctx, masked, 125); !errors.Is(err, secret.ErrManage) {
		t.Fatal("registry proof changed without authority", err)
	}
	lists := NewRouteListStore(db.DB())
	list := contractroute.RouteListDetail{ID: "remote", Name: "Remote", Type: "host", Source: contractroute.ListSource{Type: "remote", Remote: &contractroute.RemoteSource{URLs: []string{"https://example.test/public", "https://example.test/private?key=private-query"}}}}
	if err := lists.SaveRouteList(t.Context(), list, 1); err != nil {
		t.Fatal(err)
	}
	list, err = lists.GetRouteList(t.Context(), list.ID)
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := secret.Redact(list)
	if err != nil {
		t.Fatal(err)
	}
	if redacted.Source.Remote.URLs[0] != list.Source.Remote.URLs[0] || redacted.Source.Remote.URLs[1] == list.Source.Remote.URLs[1] {
		t.Fatal("URL sensitivity mismatch")
	}
	redacted.Name = "Renamed remote"
	if err := lists.SaveRouteList(ctx, redacted, 2); err != nil {
		t.Fatal("metadata save failed", err)
	}
	saved, err := lists.GetRouteList(t.Context(), list.ID)
	if err != nil || saved.Source.Remote.URLs[1] != list.Source.Remote.URLs[1] {
		t.Fatal("list edit lost URL", err)
	}
	settings := NewRouteSettingsStore(db.DB())
	current, err := settings.ListSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	config := contractroute.ListConfig{Revision: current.Revision, RefreshInterval: "0", LastRefreshTime: "0", HostIndexDisk: current.HostIndexDisk, MaxMindDBGeoIP: contractroute.MaxMindDBGeoIP{DownloadURL: "https://example.test/db?license=private-key"}}
	current, err = settings.SaveListConfig(t.Context(), config, 0)
	if err != nil {
		t.Fatal(err)
	}
	config.Revision = current.Revision
	redactedConfig, err := secret.Redact(config)
	if err != nil {
		t.Fatal(err)
	}
	redactedConfig.HostIndexDisk = !redactedConfig.HostIndexDisk
	if _, err := settings.SaveListConfig(ctx, redactedConfig, 0); err != nil {
		t.Fatal("GeoIP metadata save failed", err)
	}
}

func TestTrustedOriginsRequireSeparateSecurityAuthority(t *testing.T) {
	db, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewSettingsStore(db.DB())
	original := contractsettings.Settings{TrustedOrigins: []string{"https://ui.example"}}
	if _, err := store.Save(t.Context(), original); err != nil {
		t.Fatal(err)
	}
	next := original
	next.IPv6 = true
	if _, err := store.Save(secret.WithCapabilities(t.Context(), secret.Capabilities{}), next); err != nil {
		t.Fatal("ordinary setting denied", err)
	}
	next.TrustedOrigins = []string{"https://untrusted.example"}
	if _, err := store.Save(secret.WithCapabilities(t.Context(), secret.Capabilities{Manage: true, Execute: true}), next); !errors.Is(err, secret.ErrSecurity) {
		t.Fatal("settings writer changed trust boundary", err)
	}
	if _, err := store.Save(secret.WithCapabilities(t.Context(), secret.Capabilities{Security: true}), next); err != nil {
		t.Fatal("security writer failed", err)
	}
}
