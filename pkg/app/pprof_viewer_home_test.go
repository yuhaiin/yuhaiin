package app

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	runtimepprof "runtime/pprof"
	"strings"
	"testing"
)

// Run in a fresh process because HOME and XDG_CONFIG_HOME are process-global.
// A normal CI runner has HOME set and would never exercise the failure path.
func TestProfilerViewerWithoutHome(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProfilerViewerNoHomeSubprocess$")
	env := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "HOME=") ||
			strings.HasPrefix(entry, "XDG_CONFIG_HOME=") ||
			strings.HasPrefix(entry, "YUHAIIN_PPROF_NO_HOME_TEST=") {
			continue
		}
		env = append(env, entry)
	}
	cmd.Env = append(env, "YUHAIIN_PPROF_NO_HOME_TEST="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pprof Viewer without HOME: %v\n%s", err, out)
	}
}

func TestProfilerViewerNoHomeSubprocess(t *testing.T) {
	dataDir := os.Getenv("YUHAIIN_PPROF_NO_HOME_TEST")
	if dataDir == "" {
		return
	}
	if _, err := os.UserConfigDir(); err == nil {
		t.Skip("platform resolves a user config directory even without HOME")
	}
	if err := prepareProfilerViewerConfigDir(dataDir); err != nil {
		t.Fatalf("prepare pprof config: %v", err)
	}
	if got := os.Getenv("HOME"); got != "" {
		t.Fatalf("HOME was unexpectedly set: %q", got)
	}
	want := filepath.Join(dataDir, "pprof-config")
	if got := os.Getenv("XDG_CONFIG_HOME"); got != want {
		t.Fatalf("XDG_CONFIG_HOME = %q, want %q", got, want)
	}
	info, err := os.Stat(want)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("viewer config directory was not created")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("config directory permissions = %v, want 0700", info.Mode().Perm())
	}
	if err := prepareProfilerViewerConfigDir(dataDir); err != nil {
		t.Fatalf("repeated registration: %v", err)
	}

	var data bytes.Buffer
	if err := runtimepprof.Lookup("heap").WriteTo(&data, 0); err != nil {
		t.Fatal(err)
	}
	var v profilerView
	handlers, err := v.handlersFor(data.Bytes())
	if err != nil {
		t.Fatalf("official pprof Viewer failed without HOME: %v", err)
	}
	for _, path := range []string{"/flamegraph", "/top"} {
		h := handlers[path]
		if h == nil {
			t.Errorf("missing official Viewer route %s", path)
			continue
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s: HTTP %d: %.200s", path, w.Code, w.Body.String())
		}
	}
}

func TestProfilerViewerPreservesExistingConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if resolved, err := os.UserConfigDir(); err != nil || resolved != dir {
		t.Skip("platform does not honor XDG_CONFIG_HOME")
	}
	if err := prepareProfilerViewerConfigDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("XDG_CONFIG_HOME"); got != dir {
		t.Fatalf("overwrote configured XDG_CONFIG_HOME: %q", got)
	}
}

func TestProfilerViewerConfigDirectoryError(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if _, err := os.UserConfigDir(); err == nil {
		t.Skip("platform resolves a user config directory without HOME")
	}
	dir := filepath.Join(t.TempDir(), "file-not-directory")
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareProfilerViewerConfigDir(dir); err == nil {
		t.Fatal("expected error when profile config directory is not writable")
	}
	if got := os.Getenv("XDG_CONFIG_HOME"); got != "" {
		t.Fatalf("modified XDG_CONFIG_HOME after failure: %q", got)
	}
}
