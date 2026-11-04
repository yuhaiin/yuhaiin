package sqliteabi

import (
	"slices"
	"testing"
)

func TestGlibcABIBaseline(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"GLIBC_2.2.5", false}, {"GLIBC_2.9", false}, {"GLIBC_2.16", false},
		{"GLIBC_2.17", true}, {"GLIBC_2.17.1", true}, {"GLIBC_2.18", true},
		{"GLIBC_2.44", true}, {"GLIBC_3.0", true}, {"GLIBC_PRIVATE", false}, {"MUSL_2.17", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := glibcAtLeast(tc.name, MinimumGlibc); got != tc.want {
				t.Fatalf("%s: %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestLinuxABIUsesCompatibleLibc(t *testing.T) {
	for _, tc := range []struct {
		name       string
		paths      []string
		compatible bool
		want       string
	}{
		{"glibc too old", []string{"/lib/libc.so.6"}, false, "static"},
		{"glibc supported", []string{"/lib/libc.so.6"}, true, "glibc"},
		{"musl", nil, false, "static"}, {"scratch", nil, false, "static"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			glob := func(pattern string) ([]string, error) {
				if pattern == "/lib/libc.so.6" {
					return tc.paths, nil
				}
				return nil, nil
			}
			got := linuxABI(glob, func(path string) bool { return slices.Contains(tc.paths, path) && tc.compatible })
			if got != tc.want {
				t.Fatalf("ABI: %s, want %s", got, tc.want)
			}
		})
	}
}
