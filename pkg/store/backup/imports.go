package backup

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/store/internal/conflict"
)

const MaxRecoveryImports = 2
const maxRecoveryImportMetadata = 8 << 20

// RecoveryActivationPending reads live WAL admission without migrating a store.
// A pre-import schema has no pending Web handoff.
func (s *Store) RecoveryActivationPending(ctx context.Context) (bool, error) {
	var present int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='backup_recovery_imports'").Scan(&present); err != nil {
		return false, err
	}
	if present == 0 {
		return false, nil
	}
	var active int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM backup_recovery_imports WHERE state='activating'").Scan(&active)
	return active != 0, err
}

// RecoveryImportRecord is owned by the existing backup Store. A prepared plan
// contains paths/hashes only; plaintext data remains in private staging files.
type RecoveryImportRecord struct {
	contractrecovery.Import
	Owner      string                                  `json:"owner"`
	Stage      string                                  `json:"stage,omitempty"`
	Plan       string                                  `json:"plan,omitempty"`
	Activation *contractrecovery.ImportActivateRequest `json:"activation,omitempty"`
}

func (s *Store) AddRecoveryImport(ctx context.Context, item RecoveryImportRecord) error {
	if !validRecoveryJobID(item.ID) || item.State != "uploading" || item.Owner == "" || len(item.Owner) > 256 || !item.ExpiresAt.After(item.CreatedAt) {
		return errors.New("invalid recovery upload")
	}
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM backup_recovery_imports").Scan(&count); err != nil {
		return err
	}
	if count >= MaxRecoveryImports {
		return errors.New("recovery staging is full; discard or wait for an existing import to expire")
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO backup_recovery_imports(id,expires_at,state,data_json) VALUES(?,?,?,?)", item.ID, item.ExpiresAt.UnixMilli(), item.State, string(data))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RecoveryImport(ctx context.Context, id string) (RecoveryImportRecord, error) {
	var item RecoveryImportRecord
	if !validRecoveryJobID(id) {
		return item, errors.New("invalid recovery upload identifier")
	}
	var data, state string
	var expiry int64
	err := s.db.QueryRowContext(ctx, "SELECT substr(data_json,1,?),state,expires_at FROM backup_recovery_imports WHERE id=?", maxRecoveryImportMetadata+1, id).Scan(&data, &state, &expiry)
	if err != nil {
		return item, err
	}
	if len(data) > maxRecoveryImportMetadata || json.Unmarshal([]byte(data), &item) != nil || item.ID != id || item.State != state || !validRecoveryImportState(state) || item.ExpiresAt.UnixMilli() != expiry || item.Owner == "" || len(item.Owner) > 256 || item.Size < 0 || item.Size > contractrecovery.MaxDataBytes {
		return item, errors.New("invalid recovery upload metadata")
	}
	if state == "uploaded" || state == "previewed" || state == "activating" {
		digest, err := hex.DecodeString(item.SHA256)
		if err != nil || len(digest) != 32 || item.Size == 0 {
			return item, errors.New("invalid recovery ciphertext metadata")
		}
	}
	return item, nil
}

func validRecoveryImportState(state string) bool {
	return state == "uploading" || state == "uploaded" || state == "previewed" || state == "activating" || state == "failed" || state == "deleting"
}

func (s *Store) SaveRecoveryImport(ctx context.Context, item RecoveryImportRecord, expected string) error {
	if !validRecoveryJobID(item.ID) || !validRecoveryImportState(item.State) || !validRecoveryImportState(expected) {
		return errors.New("invalid recovery upload state")
	}
	data, err := json.Marshal(item)
	if err != nil || len(data) > maxRecoveryImportMetadata {
		return errors.New("recovery upload metadata exceeds its limit")
	}
	result, err := s.db.ExecContext(ctx, "UPDATE backup_recovery_imports SET expires_at=?,state=?,data_json=? WHERE id=? AND state=?", item.ExpiresAt.UnixMilli(), item.State, string(data), item.ID, expected)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		return conflict.Err
	}
	return err
}

// AdmitRecoveryImport serializes destructive maintenance across runtime owners.
// The partial unique index supplements this transaction; capture admission also
// checks this state so neither operation can start during the other's handoff.
func (s *Store) AdmitRecoveryImport(ctx context.Context, item RecoveryImportRecord) error {
	if item.State != "activating" || item.Activation == nil || item.Activation.ID != item.ID || !validRecoveryJobID(item.PreviewID) {
		return errors.New("invalid recovery activation admission")
	}
	data, err := json.Marshal(item)
	if err != nil || len(data) > maxRecoveryImportMetadata {
		return errors.New("recovery activation metadata exceeds its limit")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var active int
	if err := tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM backup_recovery_imports WHERE state='activating') + (SELECT count(*) FROM backup_recovery_history WHERE state IN ('queued','capturing'))").Scan(&active); err != nil {
		return err
	}
	if active != 0 {
		return contract.ErrBusy
	}
	result, err := tx.ExecContext(ctx, "UPDATE backup_recovery_imports SET state='activating',data_json=? WHERE id=? AND state='previewed'", string(data), item.ID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return conflict.Err
	}
	return tx.Commit()
}

func (s *Store) RecoveryImportIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM backup_recovery_imports ORDER BY expires_at,id LIMIT ?", MaxRecoveryImports+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if !validRecoveryJobID(id) || len(out) >= MaxRecoveryImports {
			return nil, errors.New("recovery import registry exceeds its bounds")
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) DeleteRecoveryImport(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM backup_recovery_imports WHERE id=? AND state='deleting'", id)
	return err
}

func (s *Store) NextRecoveryImportExpiry(ctx context.Context) (time.Time, error) {
	var expiry sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT min(expires_at) FROM backup_recovery_imports").Scan(&expiry); err != nil {
		return time.Time{}, err
	}
	if !expiry.Valid {
		return time.Time{}, nil
	}
	return time.UnixMilli(expiry.Int64), nil
}
