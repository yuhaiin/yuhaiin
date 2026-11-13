//go:build linux || darwin

package servicehost

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLaunchd simulates the "launchctl print" PID sequence of one system job.
type fakeLaunchd struct {
	mu    sync.Mutex
	pids  []int // returned by successive prints; the last value repeats
	calls [][]string
}

func (f *fakeLaunchd) run(args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, args)
	if args[0] != "print" {
		return nil, nil
	}
	pid := f.pids[0]
	if len(f.pids) > 1 {
		f.pids = f.pids[1:]
	}
	if pid == 0 {
		return []byte("system/com.asutorufa.yuhaiin = {\n\tstate = not running\n}\n"), nil
	}
	return fmt.Appendf(nil, "system/com.asutorufa.yuhaiin = {\n\tstate = running\n\tpid = %d\n}\n", pid), nil
}

func (f *fakeLaunchd) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, call := range f.calls {
		if call[0] != "print" {
			out = append(out, strings.Join(call, " "))
		}
	}
	return out
}

func useFakeLaunchd(t *testing.T, pids ...int) *fakeLaunchd {
	t.Helper()
	fake := &fakeLaunchd{pids: pids}
	oldRun, oldStart, oldStable, oldPoll := darwinLaunchctl, darwinStartTimeout, darwinStableDuration, darwinPollInterval
	darwinLaunchctl = fake.run
	darwinStartTimeout, darwinStableDuration, darwinPollInterval = time.Second, 50*time.Millisecond, time.Millisecond
	t.Cleanup(func() {
		darwinLaunchctl, darwinStartTimeout, darwinStableDuration, darwinPollInterval = oldRun, oldStart, oldStable, oldPoll
	})
	return fake
}

func TestStartDarwinKeepsInstanceStartedByBootstrap(t *testing.T) {
	fake := useFakeLaunchd(t, 4242)
	pid, err := StartDarwin("com.asutorufa.yuhaiin")
	if err != nil || pid != 4242 {
		t.Fatalf("StartDarwin() = %d, %v; want 4242", pid, err)
	}
	if commands := fake.commands(); len(commands) != 0 {
		t.Fatalf("running instance must not be kicked or killed, got %q", commands)
	}
}

func TestStartDarwinKickstartsWithoutKill(t *testing.T) {
	fake := useFakeLaunchd(t, 0, 0, 0, 77)
	pid, err := StartDarwin("com.asutorufa.yuhaiin")
	if err != nil || pid != 77 {
		t.Fatalf("StartDarwin() = %d, %v; want 77", pid, err)
	}
	want := []string{"kickstart system/com.asutorufa.yuhaiin"}
	if commands := fake.commands(); !slices.Equal(commands, want) {
		t.Fatalf("commands = %q, want %q", commands, want)
	}
}

func TestStartDarwinTimesOut(t *testing.T) {
	useFakeLaunchd(t, 0)
	darwinStartTimeout = 10 * time.Millisecond
	if _, err := StartDarwin("com.asutorufa.yuhaiin"); err == nil {
		t.Fatal("StartDarwin() succeeded without a running process")
	}
}

func TestWaitDarwinStable(t *testing.T) {
	useFakeLaunchd(t, 10)
	if err := WaitDarwinStable("com.asutorufa.yuhaiin", 10); err != nil {
		t.Fatalf("stable process rejected: %v", err)
	}
}

func TestWaitDarwinStableDetectsRelaunch(t *testing.T) {
	// The started process exits on the lock error and KeepAlive relaunches it.
	for _, pids := range [][]int{{10, 10, 0}, {10, 11}} {
		useFakeLaunchd(t, pids...)
		if err := WaitDarwinStable("com.asutorufa.yuhaiin", 10); err == nil {
			t.Fatalf("relaunch %v was not detected", pids)
		}
	}
}

func TestParseLaunchctlPrintPID(t *testing.T) {
	for out, want := range map[string]int{
		"\tpid = 123\n":           123,
		"\tstate = not running\n": 0,
		"\tpid = bogus\n":         0,
	} {
		if got := parseLaunchctlPrintPID([]byte(out)); got != want {
			t.Errorf("parseLaunchctlPrintPID(%q) = %d, want %d", out, got, want)
		}
	}
}
