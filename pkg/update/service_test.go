package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contractupdate "github.com/Asutorufa/yuhaiin/pkg/contract/update"
)

type testInstaller struct {
	dir     string
	started string
	done    chan struct{}
}

func (i *testInstaller) Supported() (bool, string) { return true, "" }
func (i *testInstaller) StagingDir() string        { return i.dir }
func (i *testInstaller) Start(_ context.Context, path string) error {
	i.started = path
	if i.done != nil {
		close(i.done)
	}
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSelectReleaseMatchesOSArchAndPrerelease(t *testing.T) {
	releases := []release{
		{Tag: "v2.0.0", Assets: []releaseAsset{{Name: "yuhaiin-linux-arm64", URL: "bin"}, {Name: "checksums.txt", URL: "sum"}}},
		{Tag: "v3.0.0-beta.1", Prerelease: true, Assets: []releaseAsset{{Name: "yuhaiin-linux-amd64v3", URL: "bin"}, {Name: "checksums.txt", URL: "sum"}}},
		{Tag: "v2.1.0", Assets: []releaseAsset{{Name: "yuhaiin-linux-amd64v3", URL: "bin"}, {Name: "checksums.txt", URL: "sum"}}},
	}
	got, ok := selectRelease(releases, "v2.0.0", false, "linux", "amd64v3")
	if !ok || got.Tag != "v2.1.0" {
		t.Fatalf("stable selection = %#v, %v", got, ok)
	}
	got, ok = selectRelease(releases, "v2.0.0", true, "linux", "amd64v3")
	if !ok || got.Tag != "v3.0.0-beta.1" {
		t.Fatalf("beta selection = %#v, %v", got, ok)
	}
}

func TestSelectMainReleaseByPublishedAt(t *testing.T) {
	old := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	newer := old.Add(time.Hour)
	releases := []release{
		{Tag: "main", Name: "main-old", Prerelease: true, PublishedAt: old, Assets: []releaseAsset{{Name: "yuhaiin-linux-amd64", URL: "old"}, {Name: "checksums.txt", URL: "sum"}}},
		{Tag: "main", Name: "main-new", Prerelease: true, PublishedAt: newer, Assets: []releaseAsset{{Name: "yuhaiin-linux-amd64", URL: "new"}, {Name: "checksums.txt", URL: "sum"}}},
	}
	got, ok := selectReleaseChannel(releases, "main-old", "old", old, contractupdate.ChannelMain, "linux", "amd64")
	if !ok || got.Tag != "main" || got.Version != "main-new" {
		t.Fatalf("main selection = %#v, %v", got, ok)
	}
	if _, ok := selectReleaseChannel(releases, "main-new", "new", newer, contractupdate.ChannelMain, "linux", "amd64"); ok {
		t.Fatal("latest rolling main release should not update itself")
	}
	if _, ok := selectReleaseChannel(releases, "main", "new", newer, contractupdate.ChannelMain, "linux", "amd64"); ok {
		t.Fatal("matching main commit should not update itself")
	}
}

func TestSelectMainReleaseUsesCommitWhenPublishedAtIsStale(t *testing.T) {
	mainRelease := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	currentBuild := mainRelease.Add(24 * time.Hour)
	releases := []release{
		{
			Tag:         "main",
			Name:        "main-new",
			Prerelease:  true,
			PublishedAt: mainRelease,
			Assets: []releaseAsset{
				{Name: "yuhaiin-darwin-arm64", URL: "new"},
				{Name: "checksums.txt", URL: "sum"},
			},
		},
	}

	got, ok := selectReleaseChannel(
		releases,
		"main-old",
		"old",
		currentBuild,
		contractupdate.ChannelMain,
		"darwin",
		"arm64",
	)
	if !ok || got.Version != "main-new" {
		t.Fatalf("main selection with stale published_at = %#v, %v", got, ok)
	}
}

func TestServiceCheckAndApplyVerifiesChecksum(t *testing.T) {
	binary := []byte("new binary")
	hash := sha256.Sum256(binary)
	checksum := hex.EncodeToString(hash[:]) + "  yuhaiin-linux-amd64\n"
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := ""
		status := http.StatusOK
		switch r.URL.Path {
		case "/releases":
			payload, _ := json.Marshal([]release{{Tag: "v2.0.0", HTMLURL: "release", Assets: []releaseAsset{{Name: "yuhaiin-linux-amd64", URL: "https://test/binary"}, {Name: "checksums.txt", URL: "https://test/checksums"}}}})
			body = string(payload)
		case "/binary":
			body = string(binary)
		case "/checksums":
			body = checksum
		default:
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	dir := t.TempDir()
	installer := &testInstaller{dir: dir, done: make(chan struct{})}
	svc := NewService(Options{HTTPClient: &http.Client{Transport: transport}, ReleasesURL: "https://test/releases", Installer: installer, CurrentVersion: "v1.0.0", TargetOS: "linux", TargetArch: "amd64"})
	result, err := svc.Check(context.Background(), "stable")
	if err != nil || !result.UpdateAvailable || result.AssetSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatalf("check = %#v, %v", result, err)
	}
	if err := svc.Apply(context.Background(), contractupdate.ApplyRequest{TargetTag: "v2.0.0"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-installer.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("installer was not started, status=%#v", svc.Status(context.Background()))
	}
	if installer.started == "" {
		t.Fatalf("installer was not started, status=%#v", svc.Status(context.Background()))
	}
	if filepath.Dir(installer.started) != dir {
		t.Fatalf("staged file=%s outside %s", installer.started, dir)
	}
	_ = os.Remove(installer.started)
}

func TestParseChecksumRejectsMissingAsset(t *testing.T) {
	if _, err := parseChecksum("deadbeef  other", "target"); err == nil {
		t.Fatal("expected missing checksum error")
	}
}
