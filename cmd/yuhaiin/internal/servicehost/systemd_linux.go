//go:build linux

package servicehost

import (
	"context"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
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

func NewRecoveryMaintainer(directory string) backupapp.RecoveryMaintainer {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil
	}
	return &installedRecoveryMaintainer{directory: absolute}
}

func (m *installedRecoveryMaintainer) Supported() (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if os.Geteuid() != 0 {
		out, err := exec.CommandContext(ctx, "loginctl", "show-user", strconv.Itoa(os.Geteuid()), "--property=Linger", "--value").Output()
		if err != nil || strings.TrimSpace(string(out)) != "yes" {
			return false, "automatic recovery requires lingering for the systemd user manager; use offline recovery or enable lingering"
		}
	}
	out, err := Systemctl(ctx, "show", "yuhaiin.service", "--property=MainPID", "--value")
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || parseErr != nil || pid != os.Getpid() {
		return false, "full backup maintenance requires this process to own the installed systemd yuhaiin.service; use offline recovery otherwise"
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return false, "systemd-run is unavailable; use offline recovery"
	}
	return true, ""
}

func (m *installedRecoveryMaintainer) StartRecovery(ctx context.Context, id string, timeout time.Duration) error {
	lease, err := lockfile.Acquire(filepath.Join(m.directory, ".recovery-maintenance.lock"))
	if err != nil {
		return err
	}
	defer lease.Close()
	return m.launchMaintenance(ctx, id, timeout, "recovery-maintenance", "recovery-maintenance-restart")
}

func (m *installedRecoveryMaintainer) StartRestore(ctx context.Context, id string, timeout time.Duration) error {
	return m.launchMaintenance(ctx, id, timeout, "recovery-restore", "recovery-restore-restart")
}

func (m *installedRecoveryMaintainer) launchMaintenance(ctx context.Context, id string, timeout time.Duration, action, restart string) error {
	if err := guardUpdate(m.directory); err != nil {
		return err
	}
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
	unit := "yuhaiin-recovery-" + id
	if action == "recovery-restore" {
		unit = "yuhaiin-restore-" + id
	}
	args := []string{"--quiet", "--no-block", "--collect", "--unit=" + unit,
		"--property=Type=exec", "--property=RuntimeMaxSec=" + strconv.FormatInt(int64((timeout+2*time.Minute)/time.Second), 10),
		"--property=ExecStopPost=:" + strconv.Quote(strings.ReplaceAll(exe, "%", "%%")) + " " + restart + " " + strconv.Quote(strings.ReplaceAll(m.directory, "%", "%%")) + " " + id,
		exe, action, m.directory, id}
	if err := SystemdRun(ctx, args...); err != nil {
		return errors.New("could not launch the independent recovery maintenance unit")
	}
	return nil
}

type Service struct{ Directory string }

// Systemctl and SystemdRun always address the calling process's service manager.
// User managers execute as their own UID/GID and must not request a group switch.
func Systemctl(ctx context.Context, args ...string) ([]byte, error) {
	if os.Geteuid() != 0 {
		args = append([]string{"--user"}, args...)
	}
	return exec.CommandContext(ctx, "systemctl", args...).Output()
}

func SystemdRun(ctx context.Context, args ...string) error {
	if os.Geteuid() != 0 {
		args = append([]string{"--user"}, args...)
	} else {
		args = append([]string{"--uid=" + strconv.Itoa(os.Geteuid()), "--gid=" + strconv.Itoa(os.Getegid())}, args...)
	}
	return exec.CommandContext(ctx, "systemd-run", args...).Run()
}

func (s Service) Stop(ctx context.Context) error {
	if err := guardUpdate(s.Directory); err != nil {
		return err
	}

	_, err := Systemctl(ctx, "stop", "yuhaiin.service")
	return err
}
func (Service) Start(ctx context.Context) error {
	_, err := Systemctl(ctx, "start", "yuhaiin.service")
	return err
}

func guardUpdate(directory string) error { return maintenance.GuardAdmission(directory) }
