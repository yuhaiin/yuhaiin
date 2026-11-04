// Package sqliteabi selects compatible Linux SQLite release variants.
package sqliteabi

import (
	"debug/elf"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// MinimumGlibc is the ABI baseline of the published Linux PureGo libraries.
// The embedded-library regression test checks the actual imported versions.
const MinimumGlibc = "2.17"

// LinuxABI chooses the usable release ABI without executing system programs.
// Older glibc, musl and unknown/scratch hosts use the fully static release.
var linuxABIResult = sync.OnceValue(detectLinuxABI)

func LinuxABI() string { return linuxABIResult() }

func detectLinuxABI() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return "static"
	}
	loader := "/lib64/ld-linux-x86-64.so.2"
	if runtime.GOARCH == "arm64" {
		loader = "/lib/ld-linux-aarch64.so.1"
	}
	if files, _ := filepath.Glob(loader); len(files) == 0 {
		return "static"
	}
	return linuxABI(filepath.Glob, glibcCompatible)
}

func linuxABI(glob func(string) ([]string, error), compatible func(string) bool) string {
	for _, pattern := range []string{"/lib/libc.so.6", "/lib64/libc.so.6", "/usr/lib/libc.so.6", "/lib/*-linux-gnu/libc.so.6", "/usr/lib/*-linux-gnu/libc.so.6"} {
		paths, _ := glob(pattern)
		if slices.ContainsFunc(paths, compatible) {
			return "glibc"
		}
	}
	return "static"
}

func glibcCompatible(path string) bool { return glibcSupports(path, MinimumGlibc) }

func glibcSupports(path, minimum string) bool {
	binary, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer binary.Close()
	if (runtime.GOARCH == "amd64" && binary.Machine != elf.EM_X86_64) || (runtime.GOARCH == "arm64" && binary.Machine != elf.EM_AARCH64) {
		return false
	}
	versions, err := binary.DynamicVersions()
	if err != nil {
		return false
	}
	for _, version := range versions {
		if glibcAtLeast(version.Name, minimum) {
			return true
		}
	}
	return false
}

func glibcAtLeast(name, minimum string) bool {
	version, ok := strings.CutPrefix(name, "GLIBC_")
	if !ok {
		return false
	}
	parts := strings.Split(version, ".")
	want := strings.Split(minimum, ".")
	if len(parts) < 2 || len(want) < 2 {
		return false
	}
	major, e1 := strconv.Atoi(parts[0])
	minor, e2 := strconv.Atoi(parts[1])
	wantMajor, e3 := strconv.Atoi(want[0])
	wantMinor, e4 := strconv.Atoi(want[1])
	return e1 == nil && e2 == nil && e3 == nil && e4 == nil && (major > wantMajor || major == wantMajor && minor >= wantMinor)
}

// SupportsGlibc checks a target's additional versioned ELF dependencies.
func SupportsGlibc(minimum string) bool {
	if LinuxABI() != "glibc" {
		return false
	}
	return linuxABI(filepath.Glob, func(path string) bool { return glibcSupports(path, minimum) }) == "glibc"
}
