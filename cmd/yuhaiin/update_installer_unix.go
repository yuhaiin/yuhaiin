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
	args := []string{"list", u.service}
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
	if runtime.GOOS == "linux" {
		service, manager = "yuhaiin.service", "systemctl"
		stopArgs, startArgs = []string{"stop", service}, []string{"start", service}
	}
	log.Info("update helper stopping service", "service", service)
	if err := exec.Command(manager, stopArgs...).Run(); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	if runtime.GOOS == "darwin" {
		log.Info("update helper waiting for service to stop", "service", service)
		if err := waitForDarwinServiceStop(service); err != nil {
			return err
		}
	}
	log.Info("update helper replacing executable", "target", target)
	backup := target + ".update-backup"
	_ = os.Remove(backup)
	if err := os.Rename(target, backup); err != nil {
		return fmt.Errorf("backup current executable: %w", err)
	}
	if err := os.Rename(staged, target); err != nil {
		_ = os.Rename(backup, target)
		return fmt.Errorf("install updated executable: %w", err)
	}
	if err := os.Chmod(target, 0755); err != nil {
		_ = os.Remove(target)
		_ = os.Rename(backup, target)
		return fmt.Errorf("set executable permissions: %w", err)
	}
	if err := exec.Command(manager, startArgs...).Run(); err != nil {
		_ = os.Remove(target)
		_ = os.Rename(backup, target)
		_ = exec.Command(manager, startArgs...).Run()
		return fmt.Errorf("start service with updated executable: %w", err)
	}
	log.Info("update helper restarted service", "service", service)
	_ = os.Remove(backup)
	return nil
}

func waitForDarwinServiceStop(service string) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, err := exec.Command("launchctl", "list", service).CombinedOutput()
		if err != nil {
			if strings.Contains(string(out), "Could not find service") {
				return nil
			}
			return fmt.Errorf("check stopped service: %w, %s", err, strings.TrimSpace(string(out)))
		}
		if updateServicePID(out) < 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for service %s to stop", service)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func updateServicePID(data []byte) int {
	for _, line := range strings.Split(string(data), "\n") {
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
