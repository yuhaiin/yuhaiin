package frontend

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
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
		URL:    "https://yuhaiin.github.io/frontend.tar.gz",
		SHA256: hex.EncodeToString(checksum[:]),
		Size:   int64(len(archive)),
	}
	feed, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	m.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/ui-update.json" {
			return response(feed), nil
		}
		if r.URL.Path == "/frontend.tar.gz" {
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
		Build: testBuild("ui-200-ota", 200), URL: "https://yuhaiin.github.io/frontend.tar.gz",
		SHA256: hex.EncodeToString(sum[:]), Size: int64(b.Len()),
	}, t.TempDir())
	if err == nil {
		t.Fatal("traversal archive was accepted")
	}
}
