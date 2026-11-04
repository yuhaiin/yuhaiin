//go:build (!cgo || sqlite_purego) && !sqlite_cgo && !android && !ios && (((linux || darwin || windows) && (amd64 || arm64)) || (freebsd && amd64))

package sqlite_test

import (
	"debug/elf"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	nativesqlite "github.com/yuhaiin/purego-sqlite"
	sqliteembed "github.com/yuhaiin/purego-sqlite-embed"
)

func TestEmbeddedLibraryAndBridge(t *testing.T) {
	if runtime.GOOS == "linux" && compatibility.LinuxABI() != "glibc" {
		t.Skip("host uses the linked CGO fallback")
	}

	path, err := sqliteembed.Path()
	if err != nil {
		t.Fatal(err)
	}
	connector, err := nativesqlite.NewConnector(":memory:", nativesqlite.WithLibrary(path))
	if err != nil {
		t.Fatal(err)
	}
	if connector.Version() != sqliteembed.SQLiteVersion {
		t.Fatalf("unexpected library: %s", connector.Version())
	}
	for _, name := range []string{"row_read_v1", "exec_scalar_v1"} {
		found, err := connector.HasFeature(name)
		if err != nil || !found {
			t.Fatalf("embedded %s: %v, %v", name, found, err)
		}
	}
	if runtime.GOOS != "linux" {
		return
	}
	info, err := sqliteembed.Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.MinimumOS != "glibc "+compatibility.MinimumGlibc {
		t.Fatalf("update ABI baseline differs from embedded library: %s", info.MinimumOS)
	}
	library, err := elf.Open(connector.LibraryPath())
	if err != nil {
		t.Fatal(err)
	}
	defer library.Close()
	symbols, err := library.ImportedSymbols()
	if err != nil {
		t.Fatal(err)
	}
	// The baseline is kept explicit so a future binary update cannot silently
	// raise the requirement while the updater still selects it for older hosts.
	for _, symbol := range symbols {
		if !strings.HasPrefix(symbol.Version, "GLIBC_") {
			continue
		}
		var major, minor, maximumMajor, maximumMinor int
		_, parseErr := fmt.Sscanf(symbol.Version, "GLIBC_%d.%d", &major, &minor)
		_, baselineErr := fmt.Sscanf(compatibility.MinimumGlibc, "%d.%d", &maximumMajor, &maximumMinor)
		if parseErr != nil || baselineErr != nil || major > maximumMajor || major == maximumMajor && minor > maximumMinor {
			t.Fatalf("unexpected libc ABI requirement: %s@%s", symbol.Name, symbol.Version)
		}
	}
}
