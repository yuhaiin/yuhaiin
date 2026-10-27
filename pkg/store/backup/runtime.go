package backup

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
)

// RecordRecoveryRuntime stores observed startup inputs so an offline backup
// can locate external listener files and resolve relative protocol references.
// Configuration exports deliberately omit these metadata keys.
func (s *Store) RecordRecoveryRuntime(ctx context.Context, inputs contract.RecoveryRuntime) error {
	if err := backuparchive.ValidateRuntime(inputs); err != nil {
		return err
	}
	data, err := json.Marshal(inputs)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "INSERT INTO metadata(key,value) VALUES('recovery_instance_id',?) ON CONFLICT(key) DO NOTHING", uuid.New().String()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO metadata(key,value) VALUES('recovery_runtime',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", string(data)); err != nil {
		return err
	}
	return tx.Commit()
}

func LoadRecoveryRuntime(ctx context.Context, db *sql.DB) (*contract.RecoveryRuntime, error) {
	var data string
	if err := db.QueryRowContext(ctx, "SELECT substr(value,1,65537) FROM metadata WHERE key='recovery_runtime'").Scan(&data); errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var inputs contract.RecoveryRuntime
	if len(data) > 64<<10 {
		return nil, errors.New("recovery startup metadata exceeds limit")
	}
	if err := json.Unmarshal([]byte(data), &inputs, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	return &inputs, nil
}
