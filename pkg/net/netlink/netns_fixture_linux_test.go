//go:build !android

package netlink

import (
	"os"
	"path/filepath"
	"testing"
)

// Two processes refer to the same socket inode, as after an inode is
// recycled in another namespace. Only the namespace member may match.
func TestProcSearchRequiresNetworkNamespace(t *testing.T) {
	root := t.TempDir()
	for _, p := range []struct{ pid, netns, exe string }{
		{"2000", "net:[111]", "/host/program"},
		{"2001", "net:[222]", "/ssh/program"},
	} {
		dir := filepath.Join(root, p.pid)
		for _, d := range []string{"fd", "ns"} {
			if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for name, target := range map[string]string{"fd/3": "socket:[5555]", "ns/net": p.netns, "exe": p.exe} {
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	uid := uint32(os.Getuid())
	for _, tc := range []struct {
		netns uint64
		pid   uint
		exe   string
	}{{111, 2000, "/host/program"}, {222, 2001, "/ssh/program"}} {
		path, pid, err := resolveProcessNameInNetNSAt(root, 5555, uid, tc.netns, defaultProcSearchCalls)
		if err != nil || pid != tc.pid || path != tc.exe {
			t.Fatalf("netns %d: path=%q pid=%d err=%v", tc.netns, path, pid, err)
		}
	}
	if path, pid, err := resolveProcessNameInNetNSAt(root, 5555, uid, 333, defaultProcSearchCalls); err == nil {
		t.Fatalf("matched a process outside the namespace: path=%q pid=%d", path, pid)
	}
	if _, pid, err := resolveProcessNameByProcSearchAt(root, 5555, uid, defaultProcSearchCalls); err != nil || pid == 0 {
		t.Fatalf("host lookup without a namespace filter failed: pid=%d err=%v", pid, err)
	}
}
