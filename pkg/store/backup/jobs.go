package backup

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"time"
	"uuid"

	"filippo.io/age"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
)

// RecoveryJob is owned by Store, alongside the existing backup settings.
// Public results omit the immutable public-key policy and destination fingerprint.
// No private backup key or duplicate S3 credential is stored in the history.
type RecoveryJob struct {
	contract.RecoveryBackup
	Policy     contract.RecoveryPolicy `json:"policy"`
	S3Digest   string                  `json:"s3Digest,omitempty"`
	DeleteFrom string                  `json:"deleteFrom,omitempty"`
}

func NormalizeRecoveryPolicy(input contract.RecoveryPolicy) (contract.RecoveryPolicy, error) {
	p := input
	if p.Target == "" {
		p.Target = "local"
	}
	if p.Target != "local" && p.Target != "s3" {
		return p, errors.New("full backup target must be local or s3")
	}
	if p.Recipient != "" {
		if len(p.Recipient) > 128 {
			return p, errors.New("invalid public backup recipient")
		}
		if _, err := age.ParseX25519Recipient(p.Recipient); err != nil {
			return p, errors.New("full backup requires a public age X25519 recipient")
		}
	}
	if p.TimeoutMinutes == 0 {
		p.TimeoutMinutes = 30
	}
	if p.IntervalMinutes == 0 {
		p.IntervalMinutes = 24 * 60
	}
	if p.KeepCount == 0 {
		p.KeepCount = 10
	}
	if p.KeepDays == 0 {
		p.KeepDays = 30
	}
	if p.TimeoutMinutes > 24*60 || p.IntervalMinutes < 60 || p.IntervalMinutes > 365*24*60 || p.KeepCount < 1 || p.KeepCount > 1000 || p.KeepDays < 1 || p.KeepDays > 3650 {
		return p, errors.New("full backup schedule, timeout or retention exceeds its limits")
	}
	if p.Enabled && (p.Recipient == "" || !p.AllowMaintenance) {
		return p, errors.New("scheduled full backups require a public recipient and explicit service-maintenance consent")
	}
	return p, nil
}

func validRecoveryJobID(id string) bool {
	value, err := uuid.Parse(id)
	return err == nil && value != (uuid.UUID{}) && value.String() == id
}

func validRecoveryJobState(state string) bool {
	switch state {
	case "queued", "capturing", "local_ready", "uploading", "verified", "failed", "deleting":
		return true
	default:
		return false
	}
}

func (s *Store) EnqueueRecovery(ctx context.Context, job RecoveryJob) error {
	if !validRecoveryJobID(job.ID) || job.State != "queued" || job.CreatedAt.IsZero() {
		return errors.New("invalid queued backup")
	}
	data, err := json.Marshal(job)
	if err != nil || len(data) > 64<<10 {
		return errors.New("invalid backup job metadata")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM backup_recovery_history").Scan(&count); err != nil {
		return err
	}
	if count >= 4096 {
		return errors.New("backup history is full; remove old backups before creating another")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO backup_recovery_history(id,created_at,state,data_json) VALUES(?,?,?,?)", job.ID, job.CreatedAt.UnixMilli(), job.State, string(data)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RecoveryJob(ctx context.Context, id string) (RecoveryJob, error) {
	var job RecoveryJob
	if !validRecoveryJobID(id) {
		return job, errors.New("invalid backup identifier")
	}
	var data, state string
	err := s.db.QueryRowContext(ctx, "SELECT substr(data_json,1,65537),state FROM backup_recovery_history WHERE id=?", id).Scan(&data, &state)
	if err != nil {
		return job, err
	}
	if len(data) > 65536 {
		return job, errors.New("backup job metadata exceeds its limit")
	}
	err = json.Unmarshal([]byte(data), &job)
	if err == nil && (job.ID != id || job.State != state || !validRecoveryJobState(state)) {
		err = errors.New("backup metadata identifier or state mismatch")
	}
	return job, err
}

// SaveRecoveryJob cannot let an old upload/maintenance process overwrite a newer
// transition. The expected state also protects explicit deletion leases.
func (s *Store) SaveRecoveryJob(ctx context.Context, job RecoveryJob, expected string) error {
	if !validRecoveryJobID(job.ID) || !validRecoveryJobState(job.State) || !validRecoveryJobState(expected) {
		return errors.New("invalid backup identifier")
	}
	data, err := json.Marshal(job)
	if err != nil || len(data) > 64<<10 {
		return errors.New("invalid backup job metadata")
	}
	result, err := s.db.ExecContext(ctx, "UPDATE backup_recovery_history SET state=?,data_json=? WHERE id=? AND state=?", job.State, string(data), job.ID, expected)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		return errors.New("backup state changed concurrently")
	}
	return err
}

func (s *Store) RecoveryHistory(ctx context.Context) ([]contract.RecoveryBackup, error) {
	return s.recoveryHistory(ctx, 1000)
}

func (s *Store) RecoveryRetentionCandidates(ctx context.Context) ([]contract.RecoveryBackup, error) {
	return s.recoveryHistory(ctx, 4096)
}

func (s *Store) recoveryHistory(ctx context.Context, limit int) ([]contract.RecoveryBackup, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT substr(data_json,1,65537) FROM backup_recovery_history ORDER BY created_at DESC,id LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []contract.RecoveryBackup{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var item contract.RecoveryBackup
		if len(data) > 65536 {
			return nil, errors.New("backup history metadata exceeds its limit")
		}
		if err := json.Unmarshal([]byte(data), &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) LastRecoveryAttempt(ctx context.Context) (time.Time, error) {
	var timestamp sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT max(created_at) FROM backup_recovery_history").Scan(&timestamp); err != nil {
		return time.Time{}, err
	}
	if !timestamp.Valid {
		return time.Time{}, nil
	}
	return time.UnixMilli(timestamp.Int64), nil
}

func (s *Store) RecoveryPending(ctx context.Context) ([]contract.RecoveryBackup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT substr(data_json,1,65537) FROM backup_recovery_history
	 WHERE state IN ('queued','capturing','uploading','deleting') OR (state='local_ready' AND json_extract(data_json,'$.target')='s3')
 ORDER BY created_at,id LIMIT 4096`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []contract.RecoveryBackup{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if len(data) > 65536 {
			return nil, errors.New("backup metadata exceeds its limit")
		}
		var item contract.RecoveryBackup
		if err := json.Unmarshal([]byte(data), &item); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) DeleteRecoveryJob(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM backup_recovery_history WHERE id=? AND state='deleting'", id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		return errors.New("backup deletion state changed")
	}
	return err
}
