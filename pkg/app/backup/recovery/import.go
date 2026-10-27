package recovery

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
)

// PreparedImport owns authenticated, projected plaintext staging. The caller
// must Close it on failure, or retain Stage with Plan in its expiring import
// record. Plan is opaque to the scheduler; only recovery interprets transactions.
type PreparedImport struct {
	Preview  contract.RecoveryRestorePreview
	Stage    string
	Plan     string
	prepared *backuparchive.Prepared
}

func (p *PreparedImport) Close() error { return p.prepared.Close() }

// PrepareImport validates the owned import location, authenticates the archive,
// checks staging space and computes a restore plan without replacing live files.
func PrepareImport(ctx context.Context, directory, id string, input io.Reader, key backuparchive.Decryption, mode string) (_ *PreparedImport, resultErr error) {
	name, err := backupfs.ImportPath(id)
	if err != nil {
		return nil, err
	}
	prepared, err := backuparchive.PrepareWithSpaceCheck(ctx, input, filepath.Join(directory, filepath.Dir(name)), key, func(bytes int64) error { return backupfs.CheckStagingSpace(directory, bytes) })
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("archive authentication or staging failed; check the key, integrity and available space")
	}
	defer func() {
		if resultErr != nil {
			_ = prepared.Close()
		}
	}()
	preview, tx, err := prepareRecoveryRestore(ctx, directory, prepared, mode)
	if err != nil {
		return nil, err
	}
	tx.Stage, err = filepath.Rel(directory, prepared.Directory())
	if err != nil {
		return nil, err
	}
	if err := tx.validate(); err != nil {
		return nil, err
	}
	plan, err := json.Marshal(tx)
	if err != nil {
		return nil, err
	}
	return &PreparedImport{Preview: preview, Stage: tx.Stage, Plan: string(plan), prepared: prepared}, nil
}
