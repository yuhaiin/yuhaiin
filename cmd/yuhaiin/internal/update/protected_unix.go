//go:build linux || darwin

package updatecmd

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/servicehost"
	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/startuphealth"
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	updatepkg "github.com/Asutorufa/yuhaiin/pkg/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
	"net"
	"net/netip"
	"time"
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
