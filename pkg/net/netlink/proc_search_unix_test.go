//go:build (linux && !android) || darwin

package netlink

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
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
	// Measure scanning with reused buffers, as in the steady-state lookup.
	// Race instrumentation randomly discards sync.Pool entries, so measuring
	// the pool here would include unrelated scratch-buffer allocations.
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
