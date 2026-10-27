package startuphealth

import (
	"context"
	"database/sql"
	"os"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

// RecordRuntime persists the actual host startup inputs used by offline recovery.
func RecordRuntime(ctx context.Context, state interface {
	SQLDB(context.Context) (*sql.DB, error)
}, inputs contract.RecoveryRuntime) error {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return err
	}
	inputs.WorkingDirectory = workingDirectory
	db, err := state.SQLDB(ctx)
	if err != nil {
		return err
	}
	return backupstore.New(db).RecordRecoveryRuntime(ctx, inputs)
}
