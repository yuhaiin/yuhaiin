//go:build linux || darwin

package servicehost

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const darwinSystemPlist = "/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist"

func BootoutDarwin() error {
	if out, err := darwinLaunchctl("bootout", "system", darwinSystemPlist); err != nil {
		return fmt.Errorf("bootout service: %w, %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func BootstrapDarwin() error {
	if out, err := darwinLaunchctl("bootstrap", "system", darwinSystemPlist); err != nil {
		return fmt.Errorf("bootstrap service: %w, %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// darwinLaunchctl runs launchctl; tests replace it to simulate launchd.
var darwinLaunchctl = func(args ...string) ([]byte, error) {
	return exec.Command("launchctl", args...).CombinedOutput()
}

var (
	darwinStartTimeout   = 30 * time.Second
	darwinStableDuration = 12 * time.Second // longer than launchd's 10s ThrottleInterval
	darwinPollInterval   = 250 * time.Millisecond
)

// DarwinServicePID returns the PID launchd currently tracks for the system
// job, or 0 when the job is loaded but has no running process.
func DarwinServicePID(service string) (int, error) {
	out, err := darwinLaunchctl("print", "system/"+service)
	if err != nil {
		return 0, fmt.Errorf("inspect service: %w, %s", err, strings.TrimSpace(string(out)))
	}
	return parseLaunchctlPrintPID(out), nil
}

func parseLaunchctlPrintPID(out []byte) int {
	for line := range strings.SplitSeq(string(out), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "pid = "); ok {
			if pid, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && pid > 0 {
				return pid
			}
		}
	}
	return 0
}

// StartDarwin starts the loaded job without ever replacing a running
// instance and returns the PID launchd tracks.
//
// bootstrap already launches a RunAtLoad/KeepAlive job. The previous
// "kickstart -k" right after bootstrap killed and relaunched that fresh
// instance; when the first instance survived, launchd forgot it while it kept
// the data directory lock, and the tracked instance looped on the lock error.
func StartDarwin(service string) (int, error) {
	pid, err := DarwinServicePID(service)
	if err != nil {
		return 0, err
	}
	if pid > 0 {
		return pid, nil
	}
	// Without -k, kickstart only starts a job that is not running.
	out, kickErr := darwinLaunchctl("kickstart", "system/"+service)
	deadline := time.Now().Add(darwinStartTimeout)
	for {
		pid, err := DarwinServicePID(service)
		if err != nil {
			return 0, err
		}
		if pid > 0 {
			return pid, nil
		}
		if time.Now().After(deadline) {
			if kickErr != nil {
				return 0, fmt.Errorf("kickstart service: %w, %s", kickErr, strings.TrimSpace(string(out)))
			}
			return 0, errors.New("timeout waiting for service process to start")
		}
		time.Sleep(darwinPollInterval)
	}
}

// WaitDarwinStable verifies that launchd keeps tracking the same live process
// for longer than its relaunch throttle. A replaced PID means the new process
// exited (for example because another process still holds the data
// directory lock) and KeepAlive relaunched it.
func WaitDarwinStable(service string, pid int) error {
	deadline := time.Now().Add(darwinStableDuration)
	for {
		current, err := DarwinServicePID(service)
		if err != nil {
			return err
		}
		if current != pid {
			return fmt.Errorf("service process %d exited after start (launchd now tracks pid %d); check the service log for the startup error", pid, current)
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(darwinPollInterval)
	}
}

func EnsureDarwinKeepAlive() error {
	data, err := os.ReadFile(darwinSystemPlist)
	if err != nil {
		return err
	}
	if strings.Contains(string(data), "<key>KeepAlive</key>") {
		return nil
	}
	const keepAlive = "    <key>KeepAlive</key>\n    <true/>\n\n"
	updated := strings.Replace(string(data), "</dict>", keepAlive+"</dict>", 1)
	if updated == string(data) {
		return errors.New("launchd plist does not contain a dictionary")
	}
	tmp := darwinSystemPlist + ".update"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, []byte(updated), 0700); err != nil {
		return err
	}
	if err := os.Rename(tmp, darwinSystemPlist); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func WaitDarwinExit(pid int) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("check stopped service process %d: %w", pid, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for service process %d to stop", pid)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
