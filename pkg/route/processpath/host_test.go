package processpath

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestHostExecutableMatches uses the running test binary, so the path has
// the real shape this platform reports.
func TestHostExecutableMatches(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	f := Host()
	dir := filepath.Dir(exe)
	b := NewBuilder(f)
	for entry, list := range map[string]string{
		exe:                                "exact",
		filepath.Join(dir, "**"):           "directory",
		"**/" + filepath.Base(dir) + "/**": "any-depth",
		filepath.Join(dir+"-other", "**"):  "similar",
		strings.ToUpper(exe):               "upper",
		filepath.Join(filepath.Dir(dir), "*", filepath.Base(exe)): "star",
	} {
		if _, err := b.Add(entry, list); err != nil {
			t.Fatalf("Add(%q): %v", entry, err)
		}
	}
	got := b.Build().Match(exe)
	for _, want := range []string{"exact", "directory", "any-depth", "star"} {
		if !slices.Contains(got, want) {
			t.Errorf("%q did not match %s: %v", exe, want, got)
		}
	}
	if slices.Contains(got, "similar") {
		t.Errorf("similar directory matched: %v", got)
	}
	// Case is ignored only on Windows.
	if upper := slices.Contains(got, "upper"); upper != (runtime.GOOS == "windows") && strings.ToUpper(exe) != exe {
		t.Errorf("upper-case entry matched=%v on %s", upper, runtime.GOOS)
	}
}
