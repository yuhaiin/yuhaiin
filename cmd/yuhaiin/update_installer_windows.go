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

	"github.com/Asutorufa/yuhaiin/internal/version"
	updatepkg "github.com/Asutorufa/yuhaiin/pkg/update"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type serviceUpdateInstaller struct{ target, dataDir string }

func newUpdateInstaller(dataDir string) updatepkg.Installer {
	dataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	return &serviceUpdateInstaller{target: exe, dataDir: dataDir}
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
	return exec.Command(exe, "update-helper", u.target, staged, u.dataDir).Start()
}

func updateHelper(args []string) error {
	if len(args) != 3 {
		return errors.New("update-helper requires target and staged paths")
	}
	target, staged, dataDir := args[0], args[1], args[2]
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
	stopped := false
	for time.Now().Before(deadline) {
		state, err := s.Query()
		if err == nil && state.State == svc.Stopped {
			stopped = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !stopped {
		return errors.New("timeout waiting for Windows service to stop")
	}
	if err := updatepkg.SaveHistory(dataDir, target, version.Version, version.GitCommit); err != nil {
		_ = s.Start()
		return fmt.Errorf("preserve current executable: %w", err)
	}
	backup := target + ".update-backup"
	_ = os.Remove(backup)
	if err := os.Rename(target, backup); err != nil {
		_ = s.Start()
		return err
	}
	if err := os.Rename(staged, target); err != nil {
		_ = os.Rename(backup, target)
		_ = s.Start()
		return err
	}
	if err := s.Start(); err != nil {
		_ = os.Remove(target)
		_ = os.Rename(backup, target)
		_ = s.Start()
		return fmt.Errorf("start service: %w", err)
	}
	if err := updatepkg.PruneHistory(dataDir, target); err != nil {
		// A failed prune must not make the successfully restarted service unusable.
		fmt.Fprintln(os.Stderr, "prune update history:", err)
	}
	_ = os.Remove(backup)
	return nil
}
