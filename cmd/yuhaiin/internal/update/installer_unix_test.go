//go:build linux || darwin

package updatecmd

import (
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func TestEnsureDataDirectoryReleased(t *testing.T) {
	directory := t.TempDir()
	if err := ensureDataDirectoryReleased(directory); err != nil {
		t.Fatalf("free data directory rejected: %v", err)
	}
	// A stray service process that launchd no longer tracks still holds the lock.
	held, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureDataDirectoryReleased(directory); err == nil {
		t.Fatal("held data directory was not detected")
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ensureDataDirectoryReleased(directory); err != nil {
		t.Fatalf("released data directory rejected: %v", err)
	}
}
