package route

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

type listSettingsStub struct {
	value RouteListSettings
}

func (s *listSettingsStub) ListSettings(context.Context) (RouteListSettings, error) {
	return s.value, nil
}

func (s *listSettingsStub) SaveListSettings(_ context.Context, value RouteListSettings) error {
	s.value = value
	return nil
}

func TestListsSaveContractConfigWithoutLoadedGeoIP(t *testing.T) {
	geoIPFile := t.TempDir() + "/geoip.mmdb"
	if err := os.WriteFile(geoIPFile, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	geoIPURL := (&url.URL{Scheme: "file", Path: geoIPFile}).String()

	settings := &listSettingsStub{}
	lists := &Lists{
		settings:   settings,
		downloader: NewDownloader(t.TempDir(), nil),
	}

	err := lists.SaveContractConfig(context.Background(), contractroute.ListConfig{
		RefreshInterval: "5",
		MaxMindDBGeoIP:  contractroute.MaxMindDBGeoIP{DownloadURL: geoIPURL},
	}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if settings.value.RefreshInterval != 5 || settings.value.MaxMindDBDownloadURL != geoIPURL {
		t.Fatalf("saved settings = %+v", settings.value)
	}
}

func TestListsSaveContractConfigDoesNotDownloadGeoIP(t *testing.T) {
	settings := &listSettingsStub{}
	lists := &Lists{
		settings:   settings,
		downloader: NewDownloader(t.TempDir(), nil),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	const geoIPURL = "https://example.com/geoip.mmdb"
	if err := lists.SaveContractConfig(ctx, contractroute.ListConfig{
		MaxMindDBGeoIP: contractroute.MaxMindDBGeoIP{DownloadURL: geoIPURL},
	}, 0); err != nil {
		t.Fatal(err)
	}
	if settings.value.MaxMindDBDownloadURL != geoIPURL || settings.value.MaxMindDBError != "" {
		t.Fatalf("saved settings = %+v", settings.value)
	}
}

func TestListsSaveContractConfigSwitchesHostIndexStorage(t *testing.T) {
	oldDataDir := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	t.Cleanup(func() { configuration.DataDir.Store(oldDataDir) })

	settings := &listSettingsStub{}
	lists := &Lists{
		settings: settings,
		hostTrie: newHostTrie(t.TempDir(), false),
	}
	t.Cleanup(func() {
		if err := lists.Close(); err != nil {
			t.Logf("close lists failed: %v", err)
		}
	})

	if err := lists.SaveContractConfig(context.Background(), contractroute.ListConfig{HostIndexDisk: true}, 0); err != nil {
		t.Fatal(err)
	}
	if !settings.value.HostIndexDisk || lists.hostTrie.cache == nil {
		t.Fatalf("disk host index was not enabled: settings=%+v cache=%#v", settings.value, lists.hostTrie.cache)
	}

	if err := lists.SaveContractConfig(context.Background(), contractroute.ListConfig{}, 0); err != nil {
		t.Fatal(err)
	}
	if settings.value.HostIndexDisk || lists.hostTrie.cache != nil {
		t.Fatalf("memory host index was not enabled: settings=%+v cache=%#v", settings.value, lists.hostTrie.cache)
	}
}

func TestRefreshGeoIPSkipsEmptyURL(t *testing.T) {
	lists := &Lists{downloader: NewDownloader(t.TempDir(), nil)}
	if err := lists.refreshGeoip(context.Background(), "", true); err != "" {
		t.Fatalf("refreshGeoip(empty) = %q", err)
	}
}
