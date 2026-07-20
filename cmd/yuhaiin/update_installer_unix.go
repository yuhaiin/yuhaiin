//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	updatepkg "github.com/Asutorufa/yuhaiin/pkg/update"
)

type serviceUpdateInstaller struct {
	target  string
	service string
}

func newUpdateInstaller() updatepkg.Installer {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	service := "com.asutorufa.yuhaiin"
	if runtime.GOOS == "linux" {
		service = "yuhaiin.service"
	}
	return &serviceUpdateInstaller{target: exe, service: service}
}

func (u *serviceUpdateInstaller) StagingDir() string { return filepath.Dir(u.target) }

func (u *serviceUpdateInstaller) Supported() (bool, string) {
	info, err := os.Lstat(u.target)
	if err != nil {
		return false, fmt.Sprintf("current executable is unavailable: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, "automatic updates do not replace symbolic links"
	}
	probe, err := os.CreateTemp(filepath.Dir(u.target), ".yuhaiin-update-probe-*")
	if err != nil {
		return false, fmt.Sprintf("update directory is not writable: %v", err)
	}
	probePath := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(probePath)
		return false, fmt.Sprintf("update directory is not writable: %v", err)
	}
	if err := os.Remove(probePath); err != nil {
		return false, fmt.Sprintf("update directory cleanup failed: %v", err)
	}
	manager := "launchctl"
	args := []string{"print", "system/" + u.service}
	if runtime.GOOS == "linux" {
		manager, args = "systemctl", []string{"is-active", "--quiet", u.service}
	}
	if err := exec.Command(manager, args...).Run(); err != nil {
		return false, "automatic updates require the installed yuhaiin service"
	}
	return true, ""
}

func (u *serviceUpdateInstaller) Start(_ context.Context, staged string) error {
	if filepath.Dir(staged) != filepath.Dir(u.target) {
		return errors.New("update must be staged beside the installed executable")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"update-helper", u.target, staged}
	var cmd *exec.Cmd
	if runtime.GOOS == "linux" {
		cmd = exec.Command("systemd-run", "--quiet", "--no-block", "--collect", "--unit=yuhaiin-update", exe)
		cmd.Args = append(cmd.Args, args...)
	} else {
		cmd = exec.Command(exe, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	log.Info("start update helper", "target", u.target, "staged", staged)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start update helper: %w", err)
	}
	return nil
}

func updateHelper(args []string) error {
	if len(args) != 2 {
		return errors.New("update-helper requires target and staged paths")
	}
	target, staged := args[0], args[1]
	service := "com.asutorufa.yuhaiin"
	manager := "launchctl"
	stopArgs, startArgs := []string{"stop", service}, []string{"start", service}
	var darwinPID int
	if runtime.GOOS == "linux" {
		service, manager = "yuhaiin.service", "systemctl"
		stopArgs, startArgs = []string{"stop", service}, []string{"start", service}
	}
	log.Info("update helper stopping service", "service", service)
	restoreService := func() {
		if runtime.GOOS == "darwin" {
			_ = bootstrapDarwinService()
			_, _ = kickstartDarwinService(service)
		} else {
			_ = exec.Command(manager, startArgs...).Run()
		}
	}
	if runtime.GOOS == "darwin" {
		// Boot out the job before replacing the executable. A plain start can
		// otherwise race with a job that is still stopping, and a failed start
		// leaves a RunAtLoad-only job down until the next login/reboot.
		out, err := exec.Command(manager, "list", service).CombinedOutput()
		if err != nil {
			return fmt.Errorf("find service before update: %w, %s", err, strings.TrimSpace(string(out)))
		}
		darwinPID = updateServicePID(out)
		if err := bootoutDarwinService(); err != nil {
			return err
		}
		if darwinPID > 0 {
			if err := waitForDarwinProcessExit(darwinPID); err != nil {
				restoreService()
				return err
			}
		}
	} else if err := exec.Command(manager, stopArgs...).Run(); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	log.Info("update helper replacing executable", "target", target)
	backup := target + ".update-backup"
	_ = os.Remove(backup)
	if err := os.Rename(target, backup); err != nil {
		restoreService()
		return fmt.Errorf("backup current executable: %w", err)
	}
	restore := func() {
		_ = os.Remove(target)
		_ = os.Rename(backup, target)
		restoreService()
	}
	if err := os.Rename(staged, target); err != nil {
		restore()
		return fmt.Errorf("install updated executable: %w", err)
	}
	if err := os.Chmod(target, 0755); err != nil {
		restore()
		return fmt.Errorf("set executable permissions: %w", err)
	}
	if err := startUpdatedService(manager, service, startArgs); err != nil {
		restore()
		return fmt.Errorf("start service with updated executable: %w", err)
	}
	log.Info("update helper restarted service", "service", service)
	_ = os.Remove(backup)
	return nil
}

const darwinSystemPlist = "/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist"

func bootoutDarwinService() error {
	if out, err := exec.Command("launchctl", "bootout", "system", darwinSystemPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("bootout service: %w, %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func bootstrapDarwinService() error {
	if out, err := exec.Command("launchctl", "bootstrap", "system", darwinSystemPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("bootstrap service: %w, %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func kickstartDarwinService(service string) (int, error) {
	out, err := exec.Command("launchctl", "kickstart", "-kp", "system/"+service).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("kickstart service: %w, %s", err, strings.TrimSpace(string(out)))
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("kickstart service returned invalid pid %q", strings.TrimSpace(string(out)))
	}
	return pid, nil
}

func startUpdatedService(manager, service string, startArgs []string) error {
	if runtime.GOOS == "darwin" {
		if err := ensureDarwinKeepAlive(); err != nil {
			return fmt.Errorf("update launchd plist: %w", err)
		}
		if err := bootstrapDarwinService(); err != nil {
			return err
		}
		_, err := kickstartDarwinService(service)
		return err
	}
	return exec.Command(manager, startArgs...).Run()
}

func ensureDarwinKeepAlive() error {
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

func waitForDarwinProcessExit(pid int) error {
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

func updateServicePID(data []byte) int {
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.SplitN(strings.TrimSpace(strings.TrimSuffix(line, ";")), "=", 2)
		if len(fields) != 2 || !strings.EqualFold(strings.Trim(strings.TrimSpace(fields[0]), "\""), "pid") {
			continue
		}
		pid, err := strconv.Atoi(strings.Trim(strings.TrimSpace(fields[1]), "\""))
		if err == nil {
			return pid
		}
	}
	return -1
}
