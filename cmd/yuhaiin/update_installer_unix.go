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
	"syscall"

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
	f, err := os.OpenFile(u.target, os.O_WRONLY, 0)
	if err != nil {
		return false, fmt.Sprintf("current executable is not writable: %v", err)
	}
	f.Close()
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
	}
	return cmd.Start()
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
	if err := exec.Command(manager, stopArgs...).Run(); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
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
	_ = os.Remove(backup)
	return nil
}
