//go:build linux

package updatecmd

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/startuphealth"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/servicehost"
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	updatepkg "github.com/Asutorufa/yuhaiin/pkg/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
)

func (u *serviceUpdateInstaller) ProtectedUpdateSupported() (bool, string) {
	owner := servicehost.NewRecoveryMaintainer(u.dataDir)
	if owner == nil {
		return false, "installed_host_unsupported"
	}
	return owner.Supported()
}
func (u *serviceUpdateInstaller) DataDirectory() string    { return u.dataDir }
func (u *serviceUpdateInstaller) ActiveExecutable() string { return u.target }
func (u *serviceUpdateInstaller) StartProtected(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id || parsed == (uuid.UUID{}) {
		return errors.New("invalid update operation")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// RuntimeMax and independent ExecStopPost also handle SIGKILL and host restart.
	restart := strconv.Quote(strings.ReplaceAll(exe, "%", "%%")) + " update-protected-recover " + strconv.Quote(strings.ReplaceAll(u.dataDir, "%", "%%")) + " " + id
	args := []string{"--quiet", "--no-block", "--collect", "--unit=yuhaiin-protected-update-" + id, "--uid=" + strconv.Itoa(os.Geteuid()), "--gid=" + strconv.Itoa(os.Getegid()), "--property=Type=exec", "--property=RuntimeMaxSec=25h", "--property=ExecStopPost=:" + restart, exe, "update-protected-helper", u.dataDir, id}
	return exec.CommandContext(ctx, "systemd-run", args...).Run()
}

type protectedUpdateService struct{ directory string }

func (protectedUpdateService) Stop(ctx context.Context) error {
	return exec.CommandContext(ctx, "systemctl", "stop", "yuhaiin.service").Run()
}
func (protectedUpdateService) Start(ctx context.Context) error {
	return exec.CommandContext(ctx, "systemctl", "start", "yuhaiin.service").Run()
}
func (protectedUpdateService) MainPID(ctx context.Context) (int, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", "yuhaiin.service", "--property=MainPID", "--value").Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}
func (h protectedUpdateService) Preserve(ctx context.Context, r maintenance.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return updatepkg.SaveHistory(h.directory, r.TargetPath, r.SourceVersion, r.SourceCommit)
}
func (h protectedUpdateService) Prune(ctx context.Context, r maintenance.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return updatepkg.PruneHistory(h.directory, r.TargetPath)
}
func ProtectedInstall(args []string) error {
	if len(args) != 2 {
		return errors.New("protected update helper requires directory and operation ID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour+5*time.Minute)
	defer cancel()
	return maintenance.Run(ctx, args[0], args[1], protectedUpdateService{directory: args[0]})
}
func RecoverProtected(args []string) error {
	if len(args) != 2 {
		return errors.New("protected update recovery requires directory and operation ID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return maintenance.Recover(ctx, args[0], args[1], protectedUpdateService{directory: args[0]})
}

// Keep backup.Service's existing shutdown/consistency contract explicit here.
var _ recovery.Service = protectedUpdateService{}

// ConfirmReady probes only the target's exact local listener with its public leaf
// pinned, then checks that the installed PID and listener survive a quiet period.
func (h protectedUpdateService) ConfirmReady(ctx context.Context, r maintenance.Record) error {
	address, err := netip.ParseAddrPort(r.ReadyAddress)
	if err != nil || r.ReadyAddress == "" {
		return errors.New("update readiness listener is unavailable")
	}
	var certificate *tls.Certificate
	if len(r.ReadyCertificate) > 0 {
		certificate = &tls.Certificate{Certificate: [][]byte{r.ReadyCertificate}}
	}
	if err := startuphealth.CheckListener(ctx, net.TCPAddrFromAddrPort(address), certificate); err != nil {
		return err
	}
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	pid, err := h.MainPID(ctx)
	if err != nil || pid != r.ReadyPID {
		return errors.New("update readiness process changed")
	}
	return startuphealth.CheckListener(ctx, net.TCPAddrFromAddrPort(address), certificate)
}
