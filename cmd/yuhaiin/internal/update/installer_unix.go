//go:build linux || darwin

package updatecmd

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

	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/servicehost"
	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	updatepkg "github.com/Asutorufa/yuhaiin/pkg/update"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

type serviceUpdateInstaller struct {
	target  string
	service string
	dataDir string
}

func NewInstaller(dataDir string) updatepkg.Installer {
	dataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	service := "com.asutorufa.yuhaiin"
	if runtime.GOOS == "linux" {
		service = "yuhaiin.service"
	}
	return &serviceUpdateInstaller{target: exe, service: service, dataDir: dataDir}
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
		if os.Geteuid() != 0 {
			args = append([]string{"--user"}, args...)
		}
	}
	if err := exec.Command(manager, args...).Run(); err != nil {
		return false, "automatic updates require the installed yuhaiin service"
	}
	return true, ""
}

func (u *serviceUpdateInstaller) Start(ctx context.Context, staged string) error {
	if _, _, err := updatepkg.InspectStagedCompatibility(ctx, staged, u.dataDir); err != nil {
		return err
	}
	if filepath.Dir(staged) != filepath.Dir(u.target) {
		return errors.New("update must be staged beside the installed executable")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"update-helper", u.target, staged, u.dataDir}
	var cmd *exec.Cmd
	if runtime.GOOS == "linux" {
		runArgs := []string{"--quiet", "--no-block", "--collect", "--unit=yuhaiin-update", exe}
		if os.Geteuid() != 0 {
			runArgs = append([]string{"--user"}, runArgs...)
		}
		cmd = exec.Command("systemd-run", runArgs...)
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

func Install(args []string) error {
	if len(args) != 3 {
		return errors.New("update-helper requires target and staged paths")
	}
	target, staged, dataDir := args[0], args[1], args[2]
	if err := validateUpdateStaging(target, staged); err != nil {
		return err
	}
	defer os.Remove(staged)
	defer os.Remove(staged + ".update.json")
	if _, _, err := updatepkg.InspectStagedCompatibility(context.Background(), staged, dataDir); err != nil {
		return err
	}

	maintenance, err := lockfile.Acquire(filepath.Join(dataDir, ".recovery-maintenance.lock"))
	if err != nil {
		return err
	}
	defer maintenance.Close()
	if err := recovery.GuardServiceMaintenance(context.Background(), dataDir); err != nil {
		return err
	}
	service := "com.asutorufa.yuhaiin"
	manager := "launchctl"
	stopArgs, startArgs := []string{"stop", service}, []string{"start", service}
	var darwinPID int
	if runtime.GOOS == "linux" {
		service, manager = "yuhaiin.service", "systemctl"
		stopArgs, startArgs = []string{"stop", service}, []string{"start", service}
		if os.Geteuid() != 0 {
			stopArgs = append([]string{"--user"}, stopArgs...)
			startArgs = append([]string{"--user"}, startArgs...)
		}
	}
	log.Info("update helper stopping service", "service", service)
	restoreService := func() {
		if runtime.GOOS == "darwin" {
			_ = servicehost.BootstrapDarwin()
			_, _ = servicehost.KickstartDarwin(service)
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
		if err := servicehost.BootoutDarwin(); err != nil {
			return err
		}
		if darwinPID > 0 {
			if err := servicehost.WaitDarwinExit(darwinPID); err != nil {
				restoreService()
				return err
			}
		}
	} else if err := exec.Command(manager, stopArgs...).Run(); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	if _, _, err := updatepkg.InspectStagedCompatibility(context.Background(), staged, dataDir); err != nil {
		restoreService()
		return err
	}
	if err := updatepkg.SaveHistory(dataDir, target, version.Version, version.GitCommit); err != nil {
		restoreService()
		return fmt.Errorf("preserve current executable: %w", err)
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
	if err := updatepkg.PruneHistory(dataDir, target); err != nil {
		log.Error("prune update history failed", "err", err)
	}
	_ = os.Remove(backup)
	return nil
}

func startUpdatedService(manager, service string, startArgs []string) error {
	if runtime.GOOS == "darwin" {
		if err := servicehost.EnsureDarwinKeepAlive(); err != nil {
			return fmt.Errorf("update launchd plist: %w", err)
		}
		if err := servicehost.BootstrapDarwin(); err != nil {
			return err
		}
		_, err := servicehost.KickstartDarwin(service)
		return err
	}
	return exec.Command(manager, startArgs...).Run()
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
