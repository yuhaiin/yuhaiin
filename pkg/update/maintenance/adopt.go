package maintenance

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicfile"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

// An adoption is a separate, operator-created acknowledgement bound to one
// failed update journal. The journal itself is never rewritten: older
// binaries keep reading it unchanged, the failure evidence is preserved, and
// the recorded source executable remains startable without any adoption.
const adoptionName = ".update-adoption.json"
const maxAdoptionBytes = 1 << 20

// Failure codes which are only written before the target executable was
// installed. The updater either never renamed the source or restored it, and
// the target never ran against the deployment databases.
var preparationFailures = []string{"preparation_failed_source_preserved", "cancelled_before_maintenance"}

// PreparationFailure reports whether a terminal failure happened before any
// executable swap, so an independently verified executable may be adopted.
// starting/healthy/manual_recovery and unknown failure codes never qualify.
func PreparationFailure(r *Record) bool {
	return r != nil && r.Phase == "failed" && slices.Contains(preparationFailures, r.ErrorCode)
}

type Adoption struct {
	Version       int                          `json:"version"`
	OperationID   string                       `json:"operationId"`
	ErrorCode     string                       `json:"errorCode"`
	Executable    compatibility.Manifest       `json:"executable"`
	Compatibility contract.CompatibilityStatus `json:"compatibility"`
	AdoptedAt     time.Time                    `json:"adoptedAt"`
}

func (a Adoption) validate() error {
	if a.Version != 1 || !validID(a.OperationID) || !slices.Contains(preparationFailures, a.ErrorCode) || a.AdoptedAt.IsZero() || a.Compatibility.State != "compatible" {
		return errors.New("invalid update executable adoption")
	}
	return a.Executable.Validate()
}

func ReadAdoption(directory string) (*Adoption, error) {
	path := filepath.Join(directory, adoptionName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxAdoptionBytes || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("invalid private update adoption record")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxAdoptionBytes+1))
	if err != nil || len(data) > maxAdoptionBytes {
		return nil, errors.New("update adoption record exceeds its limit")
	}
	var a Adoption
	if err := json.Unmarshal(data, &a, json.RejectUnknownMembers(true)); err != nil {
		return nil, errors.New("invalid update adoption JSON")
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

func saveAdoption(directory string, a Adoption) error {
	if err := a.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(a)
	if err != nil || len(data) > maxAdoptionBytes {
		return errors.New("update adoption record exceeds its limit")
	}
	path := filepath.Join(directory, adoptionName)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("update adoption record must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := atomicfile.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return syncDirectory(directory)
}

// verifyAdoption accepts only the exact adopted bytes for the same failed
// operation, and rechecks the live catalogs read-only before stores open.
func verifyAdoption(ctx context.Context, directory, executable string, r *Record) error {
	a, err := ReadAdoption(directory)
	if err != nil {
		return err
	}
	if a == nil {
		return errors.New("no executable adoption is recorded")
	}
	if a.OperationID != r.ID || a.ErrorCode != r.ErrorCode {
		return errors.New("the executable adoption belongs to another update operation")
	}
	if err := verify(ctx, executable, a.Executable); err != nil {
		return fmt.Errorf("installed executable differs from the adopted executable: %w", err)
	}
	status, err := a.Executable.Check(ctx, directory)
	if err != nil || status.State != "compatible" {
		return fmt.Errorf("adopted executable no longer matches the database schema (%s)", status.State)
	}
	return nil
}

// AdoptOptions describe the running executable. The migration catalog in a
// Describe result is always the caller's own compiled catalog, so only the
// running image may adopt itself.
type AdoptOptions struct {
	Executable, Platform, Architecture string
	DryRun                             bool
}

// Adopt records the operator's explicit decision to keep a manually installed
// executable after an update failed during preparation. It requires stopped
// writers, the shared maintenance lease, no pending database recovery, the
// installed regular file to be this process image and a read-only schema
// check proving that this binary starts without a database migration.
func Adopt(ctx context.Context, directory string, options AdoptOptions) (*Adoption, error) {
	lease, err := lockfile.Acquire(filepath.Join(directory, ".recovery-maintenance.lock"))
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return nil, errors.New("another update, backup or restore maintenance owner is active; wait for it to finish")
	}
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return nil, errors.New("the service or an offline recovery owns the deployment databases; stop it before adopting an executable")
	}
	if err != nil {
		return nil, err
	}
	defer lifecycle.Close()
	if err := recovery.GuardMaintenance(directory); err != nil {
		return nil, err
	}
	var result *Adoption
	err = withJournalLock(ctx, directory, func() error {
		r, err := Read(directory)
		if err != nil {
			return err
		}
		if r == nil {
			return errors.New("no update operation is recorded; no adoption is required")
		}
		if !PreparationFailure(r) {
			return fmt.Errorf("update operation %s is %s/%s; executable adoption is only available after a preparation failure", r.ID, r.Phase, r.ErrorCode)
		}
		if _, err := os.Lstat(r.TargetPath + ".update-backup"); err == nil {
			return errors.New("an update executable recovery copy exists; preserve it and review the swap offline")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		installed, err := os.Lstat(r.TargetPath)
		if err != nil || !installed.Mode().IsRegular() {
			return errors.New("the installed executable must be a regular file, not a symbolic link")
		}
		self, err := os.Stat(options.Executable)
		if err != nil || !os.SameFile(self, installed) {
			return fmt.Errorf("run update-adopt from the installed executable %s", r.TargetPath)
		}
		m, err := compatibility.Describe(ctx, r.TargetPath, options.Platform, options.Architecture)
		if err != nil {
			return err
		}
		if m.SHA256 == r.SourceSHA256 {
			return errors.New("the recorded source executable is installed; start the service without adoption")
		}
		if err := m.VerifyPlatform(r.TargetPath); err != nil {
			return err
		}
		if err := compatibility.VerifyHostLibc(r.TargetPath); err != nil {
			return err
		}
		status, err := m.Check(ctx, directory)
		switch {
		case err != nil || status.State == "incompatible" || status.State == "unknown":
			return fmt.Errorf("installed executable cannot open this deployment (%s/%s); reinstall the recorded source executable %s", status.State, status.Reason, r.SourceSHA256)
		case status.State == "migration_required":
			return fmt.Errorf("installed executable would migrate the databases (configuration %d->%d, management %d->%d); reinstall the recorded source executable %s and use the protected update with a recovery point", status.CurrentConfiguration, status.TargetConfiguration, status.CurrentManagement, status.TargetManagement, r.SourceSHA256)
		case status.State != "compatible":
			return errors.New("installed executable compatibility is unknown")
		}
		// The same lease used by updates blocks an admitted database restore.
		if err := recovery.GuardServiceMaintenance(ctx, directory); err != nil {
			return err
		}
		m.Asset = filepath.Base(r.TargetPath)
		a := Adoption{Version: 1, OperationID: r.ID, ErrorCode: r.ErrorCode, Executable: m, Compatibility: status, AdoptedAt: time.Now().UTC()}
		result = &a
		if options.DryRun {
			return nil
		}
		return saveAdoption(directory, a)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
