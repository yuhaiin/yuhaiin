package recovery

import (
	"errors"
	"os"
	"path/filepath"

	backupfs "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func requireRecoveryLifecycle(directory string, lifecycle *os.File) error {
	if lifecycle == nil {
		return errors.New("recovery requires an owned lifecycle lock")
	}
	held, err := lifecycle.Stat()
	if err != nil {
		return err
	}
	actual, err := os.Lstat(filepath.Join(directory, ".configuration.lock"))
	if err != nil || !actual.Mode().IsRegular() || !os.SameFile(actual, held) {
		return errors.New("recovery lifecycle owner does not match deployment")
	}
	return sqlite.RequireClosed(filepath.Join(directory, "state.db"), filepath.Join(directory, "management.db"))
}

// Startup is returned only after the pending set is durably marked for
// one real startup attempt. Call Complete after databases/listener health pass;
// call Abort after all application/identity owners have closed on failure.
type Startup struct {
	directory string
	tx        recoveryTransaction
}

func (r *Startup) ID() string {
	if r == nil {
		return ""
	}
	return r.tx.ID
}

// BackupID binds an authenticated pending restoration to an update recovery point.
func (r *Startup) BackupID() string {
	if r == nil {
		return ""
	}
	return r.tx.BackupID
}

// InstanceID identifies the authenticated restored deployment, distinguishing a
// clone from recovery of the source instance even when the archive ID matches.
func (r *Startup) InstanceID() string {
	if r == nil {
		return ""
	}
	return r.tx.InstanceID
}

func (r *Startup) Complete() error {
	if r == nil {
		return nil
	}
	r.tx.Phase = "committed"
	if err := saveRecoveryTransaction(r.directory, r.tx); err != nil {
		return err
	}
	// The committed journal remains authoritative until its history/result
	// records can be persisted. Failure here cannot undo a committed service.
	_ = saveRecoveryPointRecord(r.directory, r.tx)
	_ = saveRecoveryResult(r.directory, r.tx, "committed")
	return nil
}

func (r *Startup) Abort() error {
	if r == nil {
		return nil
	}
	return rollbackRecoverySet(r.directory, &r.tx)
}

// GuardMaintenance is used by other offline writers under the lifecycle
// lock. A pending activation cannot be exported or edited as a coherent store.
func GuardMaintenance(directory string) error {
	tx, err := readRecoveryTransaction(directory)
	if err != nil {
		return err
	}
	if tx != nil && tx.Phase != "committed" {
		return errors.New("deployment has a pending recovery; complete startup or use recovery rollback first")
	}
	return nil
}

func Rollback(directory, transactionID string, maintenance bool) error {
	if !maintenance {
		return errors.New("offline rollback requires confirmed stopped writers")
	}
	directory, err := backupfs.CanonicalDirectory(directory)
	if err != nil {
		return err
	}
	lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		return err
	}
	defer lifecycle.Close()
	if err := requireRecoveryLifecycle(directory, lifecycle); err != nil {
		return err
	}
	tx, err := readRecoveryTransaction(directory)
	if err != nil {
		return err
	}
	if tx == nil || tx.ID != transactionID || tx.Phase == "committed" {
		return errors.New("rollback requires the matching pending recovery transaction")
	}
	return rollbackRecoverySet(directory, tx)
}

func PrepareStartup(directory string, lifecycle *os.File, inputs contractrecovery.Runtime) (*Startup, error) {
	tx, err := readRecoveryTransaction(directory)
	if err != nil || tx == nil {
		return nil, err
	}
	if err := requireRecoveryLifecycle(directory, lifecycle); err != nil {
		return nil, err
	}
	if tx.Phase == "committed" {
		if err := errors.Join(saveRecoveryPointRecord(directory, *tx), saveRecoveryResult(directory, *tx, "committed")); err != nil {
			return nil, nil
		}
		if err := os.Remove(filepath.Join(directory, recoveryJournalName)); err != nil {
			return nil, err
		}
		return nil, backupfs.SyncDirectory(directory)
	}
	if tx.Phase != "awaiting_startup" {
		return nil, errors.Join(errors.New("interrupted recovery was rolled back; review the recovery point and restart"), rollbackRecoverySet(directory, tx))
	}
	if inputs.ManagementAuth != tx.Runtime.ManagementAuth || inputs.ManagementTLS != tx.Runtime.ManagementTLS || inputs.ManagedCertificateID != tx.Runtime.ManagedCertificateID || inputs.CertificateFile != tx.Runtime.CertificateFile || inputs.KeyFile != tx.Runtime.KeyFile || inputs.ExternalWebDirectory != tx.Runtime.ExternalWebDirectory {
		return nil, errors.New("startup TLS/authentication/file inputs do not match the restored deployment; use the inputs returned by recovery restore or roll back")
	}
	if tx.AdoptStartup && (inputs.WorkingDirectory != tx.Runtime.WorkingDirectory || tx.Runtime.ListenAddress != "" && inputs.ListenAddress != tx.Runtime.ListenAddress) {
		return nil, errors.New("startup working directory or listener does not match the managed recovery")
	}
	tx.Phase = "checking"
	if err := saveRecoveryTransaction(directory, *tx); err != nil {
		return nil, err
	}
	return &Startup{directory: directory, tx: *tx}, nil
}

// CheckStartup admits an application only when no recovery is pending or its
// host owns the controlled startup attempt established by PrepareStartup.
func CheckStartup(directory, startupID string) error {
	tx, err := readRecoveryTransaction(directory)
	if err != nil || tx == nil {
		return err
	}
	if tx.Phase == "committed" {
		return nil
	}
	if tx.Phase != "checking" || tx.ID != startupID {
		return errors.New("deployment has a pending recovery; complete controlled startup or use offline rollback")
	}
	return nil
}
