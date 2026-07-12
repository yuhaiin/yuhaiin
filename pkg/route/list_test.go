package route

import (
	"context"
	"net/url"
	"os"
	"testing"

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

func TestRefreshGeoIPSkipsEmptyURL(t *testing.T) {
	lists := &Lists{downloader: NewDownloader(t.TempDir(), nil)}
	if err := lists.refreshGeoip(context.Background(), "", true); err != "" {
		t.Fatalf("refreshGeoip(empty) = %q", err)
	}
}
