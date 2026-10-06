//go:build (linux && !android) || darwin

package netlink

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func procSearchFixture(t testing.TB) (string, uint32, uint32) {
	t.Helper()
	root := t.TempDir()
	for pid := 1000; pid < 1032; pid++ {
		p := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(filepath.Join(p, "fd"), 0700); err != nil {
			t.Fatal(err)
		}
		for fd := range 64 {
			if err := os.Symlink("socket:[1234]", filepath.Join(p, "fd", strconv.Itoa(fd))); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink("/example/program", filepath.Join(p, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(root, "1031", "fd", "63")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[4321]", filepath.Join(root, "1031", "fd", "63")); err != nil {
		t.Fatal(err)
	}
	return root, 4321, uint32(os.Getuid())
}

func TestProcSearchAllocationBudget(t *testing.T) {
	root, inode, uid := procSearchFixture(t)
	// Measure scanning with reusable storage: race builds deliberately drop
	// sync.Pool entries at random, and normal GC can also discard pool buffers.
	scratch := new(procSearchBuffers)
	lookup := func() {
		path, pid, err := findProcessInProc(root, inode, uid, defaultProcSearchCalls, scratch)
		if err != nil || pid != 1031 || path != "/example/program" {
			t.Fatalf("path=%q pid=%d err=%v", path, pid, err)
		}
	}
	lookup()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 10 {
		lookup()
	}
	runtime.ReadMemStats(&after)
	if bytes := (after.TotalAlloc - before.TotalAlloc) / 10; bytes > 4096 {
		t.Fatalf("proc scan allocated %d bytes/query for 32 PIDs / 2048 fds; want <= 4096", bytes)
	}
}

func BenchmarkProcSearch(b *testing.B) {
	root, inode, uid := procSearchFixture(b)
	b.ReportAllocs()
	for b.Loop() {
		path, pid, err := resolveProcessNameByProcSearchAt(root, inode, uid, defaultProcSearchCalls)
		if err != nil || pid != 1031 || path != "/example/program" {
			b.Fatalf("path=%q pid=%d err=%v", path, pid, err)
		}
	}
}

func TestProcSearchMatching(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "123")
	if err := os.MkdirAll(filepath.Join(p, "fd"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[1234]", filepath.Join(p, "fd", "7")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/example/program", filepath.Join(p, "exe")); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	for _, tc := range []struct {
		name       string
		inode, uid uint32
		want       bool
	}{
		{"match", 1234, uid, true},
		{"different inode", 123, uid, false},
		{"different uid", 1234, uid + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, pid, err := resolveProcessNameByProcSearchAt(root, tc.inode, tc.uid, defaultProcSearchCalls)
			if tc.want {
				if err != nil || pid != 123 || path != "/example/program" {
					t.Fatalf("path=%q pid=%d err=%v", path, pid, err)
				}
			} else if err == nil || pid != 0 || path != "" {
				t.Fatalf("unexpected match: path=%q pid=%d err=%v", path, pid, err)
			}
		})
	}
	if err := os.Remove(filepath.Join(p, "exe")); err != nil {
		t.Fatal(err)
	}
	if _, pid, err := resolveProcessNameByProcSearchAt(root, 1234, uid, defaultProcSearchCalls); pid != 123 || err == nil {
		t.Fatalf("executable error lost: pid=%d err=%v", pid, err)
	}
	if err := os.Remove(filepath.Join(p, "fd", "7")); err != nil {
		t.Fatal(err)
	}
	if _, pid, err := resolveProcessNameByProcSearchAt(root, 1234, uid, defaultProcSearchCalls); pid != 0 || err == nil {
		t.Fatalf("removed socket still matched: pid=%d err=%v", pid, err)
	}
}

func TestProcSearchParallel(t *testing.T) {
	root, inode, uid := procSearchFixture(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 4 {
				path, pid, err := resolveProcessNameByProcSearchAt(root, inode, uid, defaultProcSearchCalls)
				if err != nil || pid != 1031 || path != "/example/program" {
					t.Errorf("path=%q pid=%d err=%v", path, pid, err)
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestProcExecutableLongPath(t *testing.T) {
	want := strings.Repeat("x", 5000)
	reads := 0
	calls := procSearchCalls{readlinkat: func(_ int, _ []byte, buf []byte) (int, error) {
		reads++
		return copy(buf, want), nil
	}}
	got, err := readProcExecutable(0, make([]byte, 4096), calls)
	if err != nil || got != want || reads != 2 {
		t.Fatalf("len=%d reads=%d err=%v", len(got), reads, err)
	}
	calls.readlinkat = func(_ int, _ []byte, _ []byte) (int, error) { return 0, unix.ENOENT }
	if _, err := readProcExecutable(0, make([]byte, 4096), calls); err != unix.ENOENT {
		t.Fatal(err)
	}
}

func TestProcNumber(t *testing.T) {
	for _, name := range []string{"self\x00", ".\x00", "..\x00", "-1\x00", "4294967296\x00", "123", "\x00"} {
		if _, ok := procNumber([]byte(name)); ok {
			t.Errorf("accepted invalid numeric name %q", name)
		}
	}
	if n, ok := procNumber([]byte("4294967295\x00")); !ok || n != ^uint32(0) {
		t.Fatalf("max uint32: n=%d ok=%t", n, ok)
	}
}

func TestProcDirectoryChunking(t *testing.T) {
	root := t.TempDir()
	for i := range 100 {
		if err := os.WriteFile(filepath.Join(root, strconv.Itoa(i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	var buf [64]byte
	var seen [100]bool
	stopped, err := scanProcDirectory(fd, buf[:], func(name []byte) bool {
		if n, ok := procNumber(name); ok && n < uint32(len(seen)) {
			if seen[n] {
				t.Errorf("duplicate directory entry %d", n)
			}
			seen[n] = true
		}
		return false
	})
	if err != nil || stopped {
		t.Fatalf("stopped=%t err=%v", stopped, err)
	}
	for i, found := range seen {
		if !found {
			t.Errorf("missing directory entry %d", i)
		}
	}
}
