package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"uuid"

	buildversion "github.com/Asutorufa/yuhaiin/internal/version"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

var errProtectedHandoffUncertain = errors.New("protected update handoff is uncertain; inspect durable status before retrying")

type RecoveryPoints interface {
	UpdateRecoveryReadiness(context.Context) (contract.RecoveryReadiness, error)
	QueueUpdateRecovery(context.Context) (contractrecovery.Backup, error)
	CancelUpdateRecovery(context.Context, string) error
}
type ProtectedInstaller interface {
	Installer
	ProtectedUpdateSupported() (bool, string)
	DataDirectory() string
	ActiveExecutable() string
	StartProtected(context.Context, string) error
}

func (s *Service) recoveryReadiness(ctx context.Context) (*contract.RecoveryReadiness, error) {
	if s.recovery == nil {
		return nil, nil
	}
	ready, err := s.recovery.UpdateRecoveryReadiness(ctx)
	if err != nil {
		return &ready, err
	}
	host, ok := s.installer.(ProtectedInstaller)
	if !ok {
		ready.Supported = false
		if ready.Enabled {
			ready.Ready = false
			ready.Reason = "installed_host_unsupported"
		}
		return &ready, nil
	}
	supported, _ := host.ProtectedUpdateSupported()
	ready.Supported = supported
	if !supported && ready.Enabled {
		ready.Ready = false
		ready.Reason = "installed_host_unsupported"
	}
	return &ready, nil
}
func (s *Service) validateUpdateConsent(ctx context.Context, status contract.CompatibilityStatus, request contract.ApplyRequest) error {
	if request.OperationID != "" {
		parsed, err := uuid.Parse(request.OperationID)
		if err != nil || parsed.String() != request.OperationID || parsed == (uuid.UUID{}) {
			return errors.New("invalid update operation ID")
		}
	}
	if status.State != "compatible" && status.State != "migration_required" {
		return errors.New("target database schema is incompatible")
	}
	ready, err := s.recoveryReadiness(ctx)
	if err != nil {
		return err
	}
	if ready == nil {
		if status.State != "compatible" {
			return errors.New("database migration requires a coordinated recovery point")
		}
		return nil
	}
	if !request.ConfirmMaintenance || !request.ConfirmManualRecovery {
		return errors.New("update requires maintenance and manual-recovery acknowledgement")
	}
	if !ready.Ready {
		return errors.New("configure a supported encrypted recovery point before updating")
	}
	if !ready.Enabled && (!request.ConfirmNoRecoveryPoint || status.State != "compatible") {
		return errors.New("database migrations require recovery protection; unprotected compatible updates need explicit confirmation")
	}
	return nil
}

func (s *Service) installPrepared(ctx context.Context, stage string, m compatibility.Manifest, id string) error {
	ready, err := s.recoveryReadiness(ctx)
	if err != nil {
		return err
	}
	if ready == nil {
		return s.installer.Start(ctx, stage)
	}
	host, ok := s.installer.(ProtectedInstaller)
	if !ok || !ready.Supported {
		if ready.Enabled {
			return errors.New("installed host cannot supervise protected updates")
		}
		return s.installer.Start(ctx, stage)
	}
	if !ready.Ready {
		return errors.New("update recovery settings changed before handoff")
	}
	if m.UpdateGuard != 1 {
		return errors.New("target does not declare protected update startup receipts")
	}
	directory := host.DataDirectory()
	owner, err := lockfile.Acquire(filepath.Join(directory, ".recovery-maintenance.lock"))
	if err != nil {
		return err
	}
	defer owner.Close()
	// The ordinary backup registry excludes simultaneous captures and Web restore
	// admission. The private update journal also serializes independent helpers.
	var point contractrecovery.Backup
	if ready.Enabled {
		point, err = s.recovery.QueueUpdateRecovery(ctx)
		if err != nil {
			return err
		}
	}
	admitted := false
	defer func() {
		if !admitted && point.ID != "" {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = s.recovery.CancelUpdateRecovery(cleanup, point.ID)
		}
	}()
	architecture := buildversion.ReleaseArch
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	source, err := compatibility.Describe(ctx, host.ActiveExecutable(), runtime.GOOS, architecture)
	if err != nil {
		return err
	}
	// Only a manifest of the actual running image can authorize later restoration.
	self, err := os.Executable()
	if err != nil {
		return err
	}
	a, err := os.Stat(self)
	if err != nil {
		return err
	}
	b, err := os.Stat(host.ActiveExecutable())
	if err != nil || !os.SameFile(a, b) {
		return errors.New("update source is not the running service executable")
	}
	if id == "" {
		id = uuid.New().String()
	}
	r := maintenance.Record{ID: id, Source: source, Target: m, TargetPath: host.ActiveExecutable(), StagedPath: stage, BackupJobID: point.ID, AllowNoPoint: !ready.Enabled, SourceVersion: s.current, SourceCommit: s.currentCommit}
	if err := maintenance.Begin(ctx, directory, r); err != nil {
		return err
	}
	admitted = true
	if err := host.StartProtected(ctx, id); err != nil {
		// Launch responses can be lost after systemd admitted the independent helper.
		// Preserve the durable operation, staging and point; never replay automatically.
		return errProtectedHandoffUncertain
	}
	return nil
}

// Cancel accepts only an unclaimed prepared handoff under the maintenance lease.
// A queued helper which starts later observes the terminal journal and cannot stop
// the service. No running capture, swap or startup can be cancelled this way.
func (s *Service) Cancel(ctx context.Context, id string) error {
	host, ok := s.installer.(ProtectedInstaller)
	if !ok {
		return errors.New("protected update cancellation is unavailable")
	}
	owner, err := lockfile.Acquire(filepath.Join(host.DataDirectory(), ".recovery-maintenance.lock"))
	if err != nil {
		return err
	}
	defer owner.Close()
	r, err := maintenance.Read(host.DataDirectory())
	if err != nil {
		return err
	}
	if r == nil || r.ID != id || (r.Phase != "prepared" && (r.Phase != "failed" || r.ErrorCode != "cancelled_before_maintenance")) {
		return errors.New("only an unclaimed prepared update may be cancelled")
	}
	observed, err := compatibility.Describe(ctx, host.ActiveExecutable(), r.Source.Platform, r.Source.Architecture)
	if err != nil || observed.SHA256 != r.SourceSHA256 {
		return errors.New("source executable changed; inspect offline update status")
	}
	if err := maintenance.SetPhase(ctx, host.DataDirectory(), id, "failed", "cancelled_before_maintenance"); err != nil {
		return err
	}
	if r.BackupJobID != "" && s.recovery != nil {
		if err := s.recovery.CancelUpdateRecovery(ctx, r.BackupJobID); err != nil {
			return err
		}
	}
	return errors.Join(removeIfPresent(r.StagedPath), removeIfPresent(r.StagedPath+compatibility.Suffix))
}
func removeIfPresent(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
