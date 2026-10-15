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

// Run in a fresh process because user config variables are process-global.
// Normal CI runners set them, which otherwise hides this regression.
func TestProfilerViewerWithoutHome(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProfilerViewerNoHomeSubprocess$")
	env := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "HOME") ||
			strings.EqualFold(name, "XDG_CONFIG_HOME") ||
			strings.EqualFold(name, "AppData") ||
			name == "YUHAIIN_PPROF_NO_HOME_TEST" {
			continue
		}
		env = append(env, entry)
	}
	cmd.Env = append(env, "YUHAIIN_PPROF_NO_HOME_TEST="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pprof Viewer without user config variables: %v\n%s", err, out)
	}
}

func TestProfilerViewerNoHomeSubprocess(t *testing.T) {
	dataDir := os.Getenv("YUHAIIN_PPROF_NO_HOME_TEST")
	if dataDir == "" {
		return
	}
	if _, err := os.UserConfigDir(); err == nil {
		t.Skip("platform resolves a user config directory without user variables")
	}
	if err := prepareProfilerViewerConfigDir(dataDir); err != nil {
		t.Fatalf("prepare pprof config: %v", err)
	}

	var envName, subDir string
	switch runtime.GOOS {
	case "windows":
		envName, subDir = "AppData", "pprof-config"
	case "darwin", "ios":
		envName, subDir = "HOME", "pprof-home"
	default:
		envName, subDir = "XDG_CONFIG_HOME", "pprof-config"
	}
	want := filepath.Join(dataDir, subDir)
	if got := os.Getenv(envName); got != want {
		t.Fatalf("%s = %q, want %q", envName, got, want)
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "ios" && os.Getenv("HOME") != "" {
		t.Fatalf("HOME was unexpectedly set: %q", os.Getenv("HOME"))
	}
	if got, err := os.UserConfigDir(); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		if expected := filepath.Join(want, "Library", "Application Support"); got != expected {
			t.Fatalf("UserConfigDir = %q, want %q", got, expected)
		}
	} else if got != want {
		t.Fatalf("UserConfigDir = %q, want %q", got, want)
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
		t.Fatalf("official pprof Viewer failed without user config variables: %v", err)
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
	var envName string
	switch runtime.GOOS {
	case "windows":
		envName = "AppData"
	case "darwin", "ios":
		envName = "HOME"
	default:
		envName = "XDG_CONFIG_HOME"
	}
	t.Setenv(envName, dir)
	before, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareProfilerViewerConfigDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv(envName); got != dir {
		t.Fatalf("overwrote configured %s: %q", envName, got)
	}
	if got, err := os.UserConfigDir(); err != nil || got != before {
		t.Fatalf("UserConfigDir changed: %q, %v", got, err)
	}
}

func TestProfilerViewerConfigDirectoryError(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AppData", "")
	if _, err := os.UserConfigDir(); err == nil {
		t.Skip("platform resolves a user config directory without user variables")
	}
	dir := filepath.Join(t.TempDir(), "file-not-directory")
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareProfilerViewerConfigDir(dir); err == nil {
		t.Fatal("expected error when the fallback directory cannot be created")
	}
	for _, name := range []string{"HOME", "AppData", "XDG_CONFIG_HOME"} {
		if got := os.Getenv(name); got != "" {
			t.Fatalf("modified %s after setup failure: %q", name, got)
		}
	}
}
