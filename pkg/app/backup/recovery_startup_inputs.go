package backup

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

// A binding exists only after an explicitly opted-in restoration. Ordinary
// deployments continue to use their host's flags. The existing transaction and
// last-result files own this binding; there is no additional TLS configuration.
type recoveryStartupBinding struct {
	InstanceID string                   `json:"instanceId"`
	Runtime    contract.RecoveryRuntime `json:"runtime"`
}

func (b recoveryStartupBinding) validate() error {
	id, err := uuid.Parse(b.InstanceID)
	if err != nil || id == (uuid.UUID{}) || id.String() != b.InstanceID {
		return errors.New("invalid managed recovery startup identity")
	}
	return backupstore.ValidateRecoveryRuntime(b.Runtime)
}

// LastRecoveryResult reads bounded public recovery metadata, never a key or
// credential. It survives a database replacement and is not configuration export.
func LastRecoveryResult(directory string) (*contract.RecoveryRestoreResult, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	const name = ".recovery-last-result.json"
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, errors.New("invalid recovery result metadata")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return nil, errors.New("cannot read bounded recovery result metadata")
	}
	var result contract.RecoveryRestoreResult
	if err := json.Unmarshal(data, &result, json.RejectUnknownMembers(true)); err != nil {
		return nil, errors.New("invalid recovery result metadata")
	}
	if result.State != "committed" && result.State != "rolled_back" {
		return nil, errors.New("unsupported recovery result state")
	}
	for _, value := range []string{result.BackupID, result.TransactionID, result.InstanceID} {
		id, err := uuid.Parse(value)
		if err != nil || id == (uuid.UUID{}) || id.String() != value {
			return nil, errors.New("invalid recovery result identity")
		}
	}
	if result.RecoveryPoint != ".recovery-point-"+result.TransactionID {
		return nil, errors.New("invalid recovery point reference")
	}
	if err := backupstore.ValidateRecoveryRuntime(result.Runtime); err != nil {
		return nil, err
	}
	return &result, nil
}

// Read the preceding policy without requiring its deployment to be readable:
// disaster recovery must still replace an explicitly confirmed damaged target.
// Ordinary startup separately verifies both directory and database identity.
func readRecoveryStartupBinding(directory string) (*recoveryStartupBinding, error) {
	tx, err := readRecoveryTransaction(directory)
	if err != nil {
		return nil, err
	}
	var binding *recoveryStartupBinding
	if tx != nil {
		// Interrupted transactions must reach PrepareRecoveryStartup's rollback
		// before TLS material or any database owner can be opened.
		if !tx.AdoptStartup || tx.Phase != "awaiting_startup" && tx.Phase != "committed" {
			return nil, nil
		}
		binding = &recoveryStartupBinding{InstanceID: tx.InstanceID, Runtime: tx.Runtime}
	} else {
		result, err := LastRecoveryResult(directory)
		if err != nil || result == nil || !result.AdoptStartup {
			return nil, err
		}
		binding = &recoveryStartupBinding{InstanceID: result.InstanceID, Runtime: result.Runtime}
	}
	return binding, nil
}

func recoveryStartupBindingFor(ctx context.Context, directory string) (*recoveryStartupBinding, error) {
	binding, err := readRecoveryStartupBinding(directory)
	if err != nil || binding == nil {
		return nil, err
	}
	canonical, err := canonicalRecoveryDirectory(directory)
	if err != nil || binding.Runtime.WorkingDirectory != canonical {
		return nil, errors.New("managed recovery startup belongs to a different deployment directory; restore with explicit path rebinding")
	}
	id, err := sqlite.RecoveryInstanceID(ctx, filepath.Join(directory, "state.db"), false)
	if err != nil || id != binding.InstanceID {
		return nil, errors.New("managed recovery startup belongs to a different or unreadable deployment")
	}
	return binding, nil
}

// ResolveRecoveryStartupInputs runs under the host's lifecycle lock, before
// opening TLS, identity or configuration owners. Invalid bindings fail closed.
func ResolveRecoveryStartupInputs(ctx context.Context, directory string, lifecycle *os.File, inputs contract.RecoveryRuntime) (contract.RecoveryRuntime, bool, error) {
	if err := requireRecoveryLifecycle(directory, lifecycle); err != nil {
		return inputs, false, err
	}
	binding, err := recoveryStartupBindingFor(ctx, directory)
	if err != nil || binding == nil {
		return inputs, false, err
	}
	if err := binding.validate(); err != nil {
		return inputs, false, err
	}
	return binding.Runtime, true, nil
}

func (b *Backup) RecoveryRestoreStatus(ctx context.Context) (contract.RecoveryRestoreStatus, error) {
	if err := ctx.Err(); err != nil {
		return contract.RecoveryRestoreStatus{}, err
	}
	tx, err := readRecoveryTransaction(b.dir)
	if err != nil {
		return contract.RecoveryRestoreStatus{}, err
	}
	if tx != nil {
		if tx.Phase != "committed" {
			return contract.RecoveryRestoreStatus{}, errors.New("restore has not completed its controlled startup checks")
		}
		// Commit is authoritative even if a failing filesystem prevented the
		// best-effort last-result/history publication. Never show older success.
		return contract.RecoveryRestoreStatus{Result: new(recoveryResult(*tx, "committed"))}, nil
	}
	result, err := LastRecoveryResult(b.dir)
	return contract.RecoveryRestoreStatus{Result: result}, err
}
