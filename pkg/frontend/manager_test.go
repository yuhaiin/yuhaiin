package frontend

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

func testBuild(version string, number int64) Build {
	return Build{Version: version, BuildNumber: number, APIContract: 1, RequiredCapabilities: []string{"rpc.v2"}}
}

func embeddedFS(b Build, index string) fs.FS {
	data, _ := json.Marshal(b)
	return fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte(index)},
		"ui-build.json": &fstest.MapFile{Data: data},
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(data []byte) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: http.Header{}}
}

func createArchive(t *testing.T, build Build) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tarWriter := tar.NewWriter(gz)
	manifest, err := json.Marshal(build)
	if err != nil {
		t.Fatal(err)
	}
	entries := []struct {
		name string
		data []byte
		dir  bool
	}{
		{"./assets/", nil, true},
		{"./index.html", []byte("remote UI"), false},
		{"./ui-build.json", manifest, false},
		{"./assets/main.js", []byte("console.log('ok')"), false},
		{"./assets/" + build.Version + ".js", []byte("// " + build.Version), false},
	}
	for _, entry := range entries {
		h := &tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.data))}
		if entry.dir {
			h.Typeflag = tar.TypeDir
			h.Mode = 0700
		}
		if err := tarWriter.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if !entry.dir {
			if _, err := tarWriter.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func installTestRelease(t *testing.T, m *Manager, build Build) {
	t.Helper()
	archive := createArchive(t, build)
	checksum := sha256.Sum256(archive)
	release := Release{
		Build:  build,
		URL:    ArchiveURL,
		SHA256: hex.EncodeToString(checksum[:]),
		Size:   int64(len(archive)),
	}
	feed, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	m.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == FeedURL {
			return response(feed), nil
		}
		if r.URL.String() == ArchiveURL {
			return response(archive), nil
		}
		t.Fatalf("unexpected request: %s", r.URL.String())
		return nil, nil
	})}
	result, err := m.Apply(context.Background(), ApplyRequest{Version: build.Version, SHA256: release.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	if result.Source != "downloaded" {
		t.Fatalf("expected downloaded UI, got %q", result.Source)
	}
}

// cancelOnEOFReader simulates a management session revoked after receiving
// the last archive byte, when HTTP download itself can still succeed.
type cancelOnEOFReader struct {
	io.Reader
	cancel context.CancelFunc
}

func (r *cancelOnEOFReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		r.cancel()
	}
	return n, err
}

func TestApplyCanceledAfterDownloadDoesNotActivate(t *testing.T) {
	m := New(t.TempDir(), embeddedFS(testBuild("ui-100-bundled", 100), "embedded"))
	build := testBuild("ui-200-ota", 200)
	archive := createArchive(t, build)
	checksum := sha256.Sum256(archive)
	release := Release{
		Build: build, URL: ArchiveURL,
		SHA256: hex.EncodeToString(checksum[:]), Size: int64(len(archive)),
	}
	feed, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == FeedURL {
			return response(feed), nil
		}
		if r.URL.String() != ArchiveURL {
			t.Fatalf("unexpected request %s", r.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       io.NopCloser(&cancelOnEOFReader{Reader: bytes.NewReader(archive), cancel: cancel}),
		}, nil
	})}
	if _, err := m.Apply(ctx, ApplyRequest{Version: build.Version, SHA256: release.SHA256}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Apply must return context.Canceled, got %v", err)
	}
	status, err := m.Status(context.Background())
	if err != nil || status.Source != "embedded" {
		t.Fatalf("canceled Apply changed selected UI: %#v %v", status, err)
	}
	restarted := New(filepath.Dir(m.root), m.embedded)
	status, err = restarted.Status(context.Background())
	if err != nil || status.Source != "embedded" {
		t.Fatalf("canceled Apply changed persistent UI: %#v %v", status, err)
	}
}

// Canceling during the durable state write must also prevent its final rename,
// not merely prevent downloads still in progress.
type cancelBeforeStateRename struct {
	checks int
}

func (c *cancelBeforeStateRename) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancelBeforeStateRename) Done() <-chan struct{}       { return nil }
func (c *cancelBeforeStateRename) Value(any) any               { return nil }
func (c *cancelBeforeStateRename) Err() error {
	c.checks++
	if c.checks > 1 {
		return context.Canceled
	}
	return nil
}

func TestWriteStateCanceledBeforeRename(t *testing.T) {
	m := New(t.TempDir(), embeddedFS(testBuild("ui-100-bundled", 100), "embedded"))
	if err := os.MkdirAll(m.root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.writeState(state{}); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelBeforeStateRename{}
	if err := m.writeStateContext(ctx, state{Current: "ui-200-ota"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation before state rename, got %v", err)
	}
	saved, err := os.ReadFile(filepath.Join(m.root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got state
	if err := json.Unmarshal(saved, &got); err != nil || got.Current != "" {
		t.Fatalf("canceled state write committed: %#v %v", got, err)
	}
}

func TestBundledUIWinsAfterBinaryUpgrade(t *testing.T) {
	dir := t.TempDir()
	initial := New(dir, embeddedFS(testBuild("ui-100-embedded", 100), "old bundled"))
	installTestRelease(t, initial, testBuild("ui-200-ota", 200))
	upgraded := New(dir, embeddedFS(testBuild("ui-300-embedded", 300), "new bundled"))
	status, err := upgraded.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Source != "embedded" || status.Active.Version != "ui-300-embedded" {
		t.Fatalf("new binary must outrank prior OTA: %#v", status)
	}
	f, err := upgraded.Open("index.html")
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(content) != "new bundled" {
		t.Fatalf("served stale UI %q: %v", content, err)
	}
	// Old hashed assets remain accessible to tabs opened before the switch.
	f, err = upgraded.Open("assets/main.js")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestOTAFallbackAndReset(t *testing.T) {
	dir := t.TempDir()
	build := testBuild("ui-100-bundled", 100)
	m := New(dir, embeddedFS(build, "embedded"))
	installTestRelease(t, m, testBuild("ui-200-ota", 200))
	resumed := New(dir, embeddedFS(build, "embedded"))
	status, _ := resumed.Status(context.Background())
	if status.Source != "downloaded" {
		t.Fatalf("OTA did not survive restart: %#v", status)
	}
	status, err := resumed.Reset(context.Background())
	if err != nil || status.Source != "embedded" {
		t.Fatalf("reset failed: %#v %v", status, err)
	}
	restarted := New(dir, embeddedFS(build, "embedded"))
	status, _ = restarted.Status(context.Background())
	if status.Source != "embedded" {
		t.Fatal("reset did not survive restart")
	}
}

func TestIncompatibleDownloadedUIIsSkipped(t *testing.T) {
	dir := t.TempDir()
	base := testBuild("ui-100-bundled", 100)
	m := New(dir, embeddedFS(base, "base"))
	installed := testBuild("ui-200-unsupported", 200)
	installed.RequiredCapabilities = []string{"rpc.v2", "unknown.future.feature"}
	data, _ := json.Marshal(installed)
	loc := filepath.Join(m.root, "versions", installed.Version)
	if err := os.MkdirAll(loc, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(loc, "ui-build.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(loc, "index.html"), []byte("wrong"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.writeState(state{Current: installed.Version}); err != nil {
		t.Fatal(err)
	}
	m = New(dir, embeddedFS(base, "base"))
	status, _ := m.Status(context.Background())
	if status.Source != "embedded" {
		t.Fatalf("incompatible OTA selected: %#v", status)
	}
}

func TestRollbackReturnsToBundled(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, embeddedFS(testBuild("ui-100-bundled", 100), "embedded"))
	installTestRelease(t, m, testBuild("ui-200-ota", 200))
	status, err := m.Rollback(context.Background())
	if err != nil || status.Source != "embedded" {
		t.Fatalf("rollback failed: %#v %v", status, err)
	}
}

func TestDownloadRejectsPathTraversal(t *testing.T) {
	m := New(t.TempDir(), embeddedFS(testBuild("ui-100-bundled", 100), "embedded"))
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	payload := []byte("outside")
	_ = tw.WriteHeader(&tar.Header{Name: "../outside", Mode: 0600, Size: int64(len(payload))})
	_, _ = tw.Write(payload)
	_ = tw.Close()
	_ = gz.Close()
	sum := sha256.Sum256(b.Bytes())
	m.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		return response(b.Bytes()), nil
	})}
	if err := os.MkdirAll(m.root, 0700); err != nil {
		t.Fatal(err)
	}
	err := m.download(context.Background(), Release{
		Build: testBuild("ui-200-ota", 200), URL: ArchiveURL,
		SHA256: hex.EncodeToString(sum[:]), Size: int64(b.Len()),
	}, t.TempDir())
	if err == nil {
		t.Fatal("traversal archive was accepted")
	}
}

// Reinstall the same release after rollback or reset. Cached immutable bundles
// must be reactivated, not rejected with "release version already exists".
func TestReactivateCachedFrontendAfterResetAndRollback(t *testing.T) {
	m := New(t.TempDir(), embeddedFS(testBuild("ui-100-embedded", 100), "embedded"))
	candidate := testBuild("ui-200-ota", 200)
	installTestRelease(t, m, candidate)
	if status, err := m.Rollback(context.Background()); err != nil || status.Source != "embedded" {
		t.Fatalf("rollback: status=%#v err=%v", status, err)
	}
	installTestRelease(t, m, candidate)
	if status, err := m.Reset(context.Background()); err != nil || status.Source != "embedded" {
		t.Fatalf("reset: status=%#v err=%v", status, err)
	}
	installTestRelease(t, m, candidate)
}

// Downloaded chunks from several previous releases must remain readable even
// after the selection state is reset to an embedded frontend.
func TestHistoricalLazyChunksRemainAfterReset(t *testing.T) {
	m := New(t.TempDir(), embeddedFS(testBuild("ui-100-embedded", 100), "embedded"))
	first := testBuild("ui-200-ota", 200)
	second := testBuild("ui-300-ota", 300)
	installTestRelease(t, m, first)
	installTestRelease(t, m, second)
	if _, err := m.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, release := range []Build{first, second} {
		name := "assets/" + release.Version + ".js"
		f, err := m.Open(name)
		if err != nil {
			t.Fatalf("lost lazy chunk %s: %v", name, err)
		}
		data, readErr := io.ReadAll(f)
		_ = f.Close()
		if readErr != nil || !strings.Contains(string(data), release.Version) {
			t.Fatalf("wrong historical chunk %s: %s, %v", name, data, readErr)
		}
	}
	if got, err := m.Open("index.html"); err != nil {
		t.Fatal(err)
	} else {
		data, readErr := io.ReadAll(got)
		_ = got.Close()
		if readErr != nil || string(data) != "embedded" {
			t.Fatalf("reset must keep embedded index: %s, %v", data, readErr)
		}
	}
}

func TestEmergencySelectionCancelsDownload(t *testing.T) {
	for _, action := range []string{"reset", "rollback"} {
		t.Run(action, func(t *testing.T) {
			m := New(t.TempDir(), embeddedFS(testBuild("ui-100-embedded", 100), "embedded"))
			installTestRelease(t, m, testBuild("ui-200-ota", 200))
			candidate := testBuild("ui-300-ota", 300)
			archive := createArchive(t, candidate)
			digest := sha256.Sum256(archive)
			release := Release{Build: candidate, URL: ArchiveURL, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(archive))}
			feed, _ := json.Marshal(release)
			started := make(chan struct{})
			resume := make(chan struct{})
			var once sync.Once
			m.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() == FeedURL {
					return response(feed), nil
				}
				once.Do(func() { close(started) })
				<-resume
				return response(archive), nil
			})}
			result := make(chan error, 1)
			go func() {
				_, err := m.Apply(context.Background(), ApplyRequest{Version: candidate.Version, SHA256: release.SHA256})
				result <- err
			}()
			<-started
			var err error
			if action == "reset" {
				_, err = m.Reset(context.Background())
			} else {
				_, err = m.Rollback(context.Background())
			}
			if err != nil {
				t.Fatal(err)
			}
			close(resume)
			if err := <-result; err == nil {
				t.Fatal("pending download reactivated the OTA after emergency action")
			}
			status, err := m.Status(context.Background())
			if err != nil || status.Source != "embedded" {
				t.Fatalf("emergency selection lost: status=%#v err=%v", status, err)
			}
		})
	}
}

// A corrupt version may retain valid metadata/index.html yet be missing one
// lazy-loaded JS file. Reset must allow a verified archive to heal the cache.
func TestRepairCachedFrontendMissingChunk(t *testing.T) {
	m := New(t.TempDir(), embeddedFS(testBuild("ui-100-embedded", 100), "embedded"))
	release := testBuild("ui-200-ota", 200)
	installTestRelease(t, m, release)
	chunk := filepath.Join(m.root, "versions", release.Version, "assets", "main.js")
	if err := os.Remove(chunk); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	check, err := m.Check(context.Background())
	if err != nil || !check.Available {
		t.Fatalf("reinstall must be offered after reset: result=%#v err=%v", check, err)
	}
	installTestRelease(t, m, release)
	data, err := os.ReadFile(chunk)
	if err != nil || string(data) != "console.log('ok')" {
		t.Fatalf("missing JS not repaired: data=%q err=%v", data, err)
	}
	got, err := m.Status(context.Background())
	if err != nil || got.Active.Version != release.Version {
		t.Fatalf("repaired release not active: status=%#v err=%v", got, err)
	}
}

func TestRepairCachedFrontendModifiedChunk(t *testing.T) {
	m := New(t.TempDir(), embeddedFS(testBuild("ui-100-embedded", 100), "embedded"))
	release := testBuild("ui-200-ota", 200)
	installTestRelease(t, m, release)
	chunk := filepath.Join(m.root, "versions", release.Version, "assets", "main.js")
	if err := os.WriteFile(chunk, []byte("bad JS"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	installTestRelease(t, m, release)
	data, err := os.ReadFile(chunk)
	if err != nil || string(data) != "console.log('ok')" {
		t.Fatalf("tampered JS not repaired: data=%q err=%v", data, err)
	}
}

// If B's entry point is missing, the selector serves A from Previous.
// Installing C must record A, not broken B, as the rollback target.
func TestApplyFromFallbackRollsBackToActuallyServedBundle(t *testing.T) {
	m := New(t.TempDir(), embeddedFS(testBuild("ui-100-embedded", 100), "embedded"))
	a := testBuild("ui-200-ota", 200)
	b := testBuild("ui-300-ota", 300)
	c := testBuild("ui-400-ota", 400)
	installTestRelease(t, m, a)
	installTestRelease(t, m, b)
	if err := os.Remove(filepath.Join(m.root, "versions", b.Version, "index.html")); err != nil {
		t.Fatal(err)
	}
	status, err := m.Status(context.Background())
	if err != nil || status.Source != "previous" || status.Active.Version != a.Version {
		t.Fatalf("expected fallback A while B is broken: status=%#v err=%v", status, err)
	}
	installTestRelease(t, m, c)
	status, err = m.Rollback(context.Background())
	if err != nil || status.Active.Version != a.Version {
		t.Fatalf("rollback must restore A, not broken B: status=%#v err=%v", status, err)
	}
}

// If both saved OTA bundles are broken and Core serves its embedded UI,
// installing a new OTA must not record either broken bundle as the predecessor.
func TestApplyFromEmbeddedFallbackRollsBackToEmbedded(t *testing.T) {
	m := New(t.TempDir(), embeddedFS(testBuild("ui-100-embedded", 100), "embedded"))
	a := testBuild("ui-200-ota", 200)
	b := testBuild("ui-300-ota", 300)
	c := testBuild("ui-400-ota", 400)
	installTestRelease(t, m, a)
	installTestRelease(t, m, b)
	for _, version := range []string{a.Version, b.Version} {
		if err := os.Remove(filepath.Join(m.root, "versions", version, "index.html")); err != nil {
			t.Fatal(err)
		}
	}
	status, err := m.Status(context.Background())
	if err != nil || status.Source != "embedded" {
		t.Fatalf("expected embedded fallback: status=%#v err=%v", status, err)
	}
	installTestRelease(t, m, c)
	status, err = m.Rollback(context.Background())
	if err != nil || status.Source != "embedded" {
		t.Fatalf("rollback must restore embedded: status=%#v err=%v", status, err)
	}
}

func TestFeedAndArchiveAreTheOfficialSiteFiles(t *testing.T) {
	const base = "https://yuhaiin.github.io/"
	if FeedURL != base+"ui-update.json" || ArchiveURL != base+"frontend.tar.gz" {
		t.Fatalf("the feed and archive must be the official site files, got %q and %q", FeedURL, ArchiveURL)
	}
	if New(t.TempDir(), embeddedFS(testBuild("ui-1-embedded", 1), "embedded")).feed != FeedURL {
		t.Fatal("manager must read the official feed")
	}
}

func TestFeedRejectsOtherArchiveURLs(t *testing.T) {
	build := testBuild("ui-2-ota", 2)
	for name, archiveURL := range map[string]string{
		"v2 release":  "https://github.com/yuhaiin/yuhaiin-react/releases/download/ui-v2/frontend.tar.gz",
		"raw branch":  "https://raw.githubusercontent.com/yuhaiin/yuhaiin.github.io/main/frontend.tar.gz",
		"other path":  "https://yuhaiin.github.io/other/frontend.tar.gz",
		"query":       ArchiveURL + "?x=1",
		"fragment":    ArchiveURL + "#x",
		"http":        "http://yuhaiin.github.io/frontend.tar.gz",
		"user info":   "https://user@yuhaiin.github.io/frontend.tar.gz",
		"other owner": "https://someone.github.io/frontend.tar.gz",
	} {
		t.Run(name, func(t *testing.T) {
			archive := createArchive(t, build)
			sum := sha256.Sum256(archive)
			feed, err := json.Marshal(Release{Build: build, URL: archiveURL, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(archive))})
			if err != nil {
				t.Fatal(err)
			}
			m := New(t.TempDir(), embeddedFS(testBuild("ui-1-embedded", 1), "embedded"))
			m.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() == FeedURL {
					return response(feed), nil
				}
				t.Fatalf("unexpected request: %s", r.URL.String())
				return nil, nil
			})}
			if _, err := m.Check(context.Background()); err == nil {
				t.Fatalf("expected %q to be rejected", archiveURL)
			}
		})
	}
}

func TestRedirectsStayOnTheOfficialSite(t *testing.T) {
	m := New(t.TempDir(), embeddedFS(testBuild("ui-1-embedded", 1), "embedded"))
	check := func(rawURL string, hops int) error {
		req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
		return m.client.CheckRedirect(req, make([]*http.Request, hops))
	}
	if err := check(ArchiveURL, 1); err != nil {
		t.Fatalf("%s should be allowed: %v", ArchiveURL, err)
	}
	for name, bad := range map[string]string{
		"v2 release": "https://github.com/yuhaiin/yuhaiin-react/releases/download/ui-v2/frontend.tar.gz",
		"asset host": "https://release-assets.githubusercontent.com/github-production-release-asset/1",
		"other host": "https://evil.example/frontend.tar.gz",
		"suffix":     "https://yuhaiin.github.io.evil.example/x",
		"plain http": "http://yuhaiin.github.io/frontend.tar.gz",
	} {
		if err := check(bad, 1); err == nil {
			t.Fatalf("%s (%s) must be rejected", name, bad)
		}
	}
	if err := check(ArchiveURL, 3); err == nil {
		t.Fatal("redirect chains longer than two hops must be rejected")
	}
}
