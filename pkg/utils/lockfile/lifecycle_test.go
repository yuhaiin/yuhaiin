package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLifecycleLockExcludesConcurrentOwnerAndKeepsInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".configuration.lock")
	first, err := Acquire(path)
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip("lifecycle lock unsupported on this platform")
	}
	if err != nil {
		t.Fatal(err)
	}
	before, err := first.Stat()
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if other, err := Acquire(path); err == nil {
			_ = other.Close()
			t.Fatal("concurrent lifecycle owner accepted")
		}
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	after, err := second.Stat()
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("lifecycle inode was replaced")
	}
	if runtime.GOOS != "windows" && after.Mode().Perm() != 0o600 {
		t.Fatal("lock permissions are not private")
	}
}

func TestLifecycleLockRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privilege depends on Windows installation")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "state.db")
	if err := os.WriteFile(target, []byte("configuration"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, ".configuration.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if file, err := Acquire(link); err == nil {
		_ = file.Close()
		t.Fatal("symlink lifecycle lock accepted")
	}
}
