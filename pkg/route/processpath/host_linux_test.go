package processpath

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLinuxDeletedExecutable runs a copy of sleep, deletes the file and reads
// /proc/PID/exe, which then carries the kernel's " (deleted)" marker.
func TestLinuxDeletedExecutable(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	copyPath := filepath.Join(dir, "yuhaiin-sleep")
	src, err := os.Open(sleep)
	if err != nil {
		t.Skip(err)
	}
	dst, err := os.OpenFile(copyPath, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(dst, src)
	_ = src.Close()
	if closeErr := dst.Close(); err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	cmd := exec.Command(copyPath, "30")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if err := os.Remove(copyPath); err != nil {
		t.Fatal(err)
	}
	var reported string
	for range 50 {
		reported, err = os.Readlink(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "exe"))
		if err == nil && strings.HasSuffix(reported, " (deleted)") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.HasSuffix(reported, " (deleted)") {
		t.Skipf("kernel reported %q", reported)
	}
	b := NewBuilder(Host())
	_, _ = b.Add(copyPath, "exact")
	_, _ = b.Add(filepath.Join(dir, "**"), "directory")
	got := b.Build().Match(reported)
	if !slices.Contains(got, "exact") || !slices.Contains(got, "directory") {
		t.Fatalf("deleted executable %q matched %v", reported, got)
	}
}
