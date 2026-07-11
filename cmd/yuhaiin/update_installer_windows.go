//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	updatepkg "github.com/Asutorufa/yuhaiin/pkg/update"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type serviceUpdateInstaller struct{ target string }

func newUpdateInstaller() updatepkg.Installer {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	return &serviceUpdateInstaller{target: exe}
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
	m, err := mgr.Connect()
	if err != nil {
		return false, "Windows service manager is unavailable"
	}
	defer m.Disconnect()
	s, err := m.OpenService("Yuhaiin")
	if err != nil {
		return false, "automatic updates require the installed yuhaiin service"
	}
	defer s.Close()
	state, err := s.Query()
	if err != nil || state.State != svc.Running {
		return false, "yuhaiin service is not running"
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
	return exec.Command(exe, "update-helper", u.target, staged).Start()
}

func updateHelper(args []string) error {
	if len(args) != 2 {
		return errors.New("update-helper requires target and staged paths")
	}
	target, staged := args[0], args[1]
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService("Yuhaiin")
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		state, err := s.Query()
		if err == nil && state.State == svc.Stopped {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	backup := target + ".update-backup"
	_ = os.Remove(backup)
	if err := os.Rename(target, backup); err != nil {
		return err
	}
	if err := os.Rename(staged, target); err != nil {
		_ = os.Rename(backup, target)
		return err
	}
	if err := s.Start(); err != nil {
		_ = os.Remove(target)
		_ = os.Rename(backup, target)
		_ = s.Start()
		return fmt.Errorf("start service: %w", err)
	}
	_ = os.Remove(backup)
	return nil
}
