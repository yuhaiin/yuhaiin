//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"uuid"

	backupapp "github.com/Asutorufa/yuhaiin/pkg/app/backup"
)

type installedRecoveryMaintainer struct{ directory string }

func newRecoveryMaintainer(directory string) backupapp.RecoveryMaintainer {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil
	}
	return &installedRecoveryMaintainer{directory: absolute}
}

func (m *installedRecoveryMaintainer) Supported() (bool, string) {
	if os.Geteuid() != 0 {
		return false, "automatic recovery maintenance currently requires a root-owned system service; use the offline recovery CLI for unprivileged installations"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "show", "yuhaiin.service", "--property=MainPID", "--value").Output()
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || parseErr != nil || pid != os.Getpid() {
		return false, "full backup maintenance requires this process to own the installed yuhaiin.service; use offline recovery otherwise"
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return false, "systemd-run is unavailable; use offline recovery"
	}
	return true, ""
}

func (m *installedRecoveryMaintainer) StartRecovery(ctx context.Context, id string, timeout time.Duration) error {
	value, err := uuid.Parse(id)
	if err != nil || value.String() != id || value == (uuid.UUID{}) {
		return errors.New("invalid recovery job identifier")
	}
	if timeout < time.Minute || timeout > 24*time.Hour {
		return errors.New("invalid recovery maintenance timeout")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// ExecStopPost belongs to the independent transient unit. It also runs if
	// the helper crashes or reaches RuntimeMaxSec, when Go defers cannot run.
	args := []string{"--quiet", "--no-block", "--collect", "--unit=yuhaiin-recovery-" + id,
		"--uid=" + strconv.Itoa(os.Geteuid()), "--gid=" + strconv.Itoa(os.Getegid()),
		"--property=Type=exec", "--property=RuntimeMaxSec=" + strconv.FormatInt(int64((timeout+2*time.Minute)/time.Second), 10),
		"--property=ExecStopPost=:" + strconv.Quote(strings.ReplaceAll(exe, "%", "%%")) + " recovery-maintenance-restart " + strconv.Quote(strings.ReplaceAll(m.directory, "%", "%%")) + " " + id,
		exe, "recovery-maintenance", m.directory, id}
	if err := exec.CommandContext(ctx, "systemd-run", args...).Run(); err != nil {
		return errors.New("could not launch the independent recovery maintenance unit")
	}
	return nil
}

type installedRecoveryService struct{}

func (installedRecoveryService) Stop(ctx context.Context) error {
	return exec.CommandContext(ctx, "systemctl", "stop", "yuhaiin.service").Run()
}
func (installedRecoveryService) Start(ctx context.Context) error {
	return exec.CommandContext(ctx, "systemctl", "start", "yuhaiin.service").Run()
}

func recoveryMaintenanceHelper(args []string) error {
	if len(args) != 2 {
		return errors.New("recovery-maintenance requires deployment directory and job identifier")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour+2*time.Minute)
	defer cancel()
	return backupapp.RunRecoveryCapture(ctx, args[0], args[1], installedRecoveryService{})
}

func recoveryMaintenanceRestartHelper(args []string) error {
	if len(args) != 2 {
		return errors.New("recovery-maintenance-restart requires deployment directory and job identifier")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return backupapp.RestartRecoveryService(ctx, args[0], args[1], installedRecoveryService{})
}
