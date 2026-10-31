package certificates

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
)

const ManualAttemptInterval = 5 * time.Minute

// Queue records an explicit initial/manual request. Manual clicks cannot defeat
// failure backoff, Retry-After, an active lease, or the minimum attempt interval.
func (s *Store) Queue(ctx context.Context, id string, revision uint64, now time.Time) (contract.Resource, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contract.Resource{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var data []byte
	var leaseUntil int64
	err = tx.QueryRowContext(ctx, `SELECT status_json,lease_until FROM managed_certificates WHERE id=? AND revision=?`, id, revision).Scan(&data, &leaseUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return contract.Resource{}, ErrConflict
	}
	if err != nil {
		return contract.Resource{}, err
	}
	if leaseUntil > now.UnixMilli() {
		return contract.Resource{}, ErrConflict
	}
	var status contract.Status
	if err = json.Unmarshal(data, &status); err != nil {
		return contract.Resource{}, err
	}
	due := now
	if minimum := status.LastAttempt.Add(ManualAttemptInterval); minimum.After(due) {
		due = minimum
	}
	if status.Failures > 0 && status.NextAttempt.After(due) {
		due = status.NextAttempt
	}
	status.State = "queued"
	status.NextAttempt = due
	data, err = json.Marshal(status)
	if err != nil {
		return contract.Resource{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE managed_certificates SET status_json=? WHERE id=? AND revision=?`, string(data), id, revision); err != nil {
		return contract.Resource{}, err
	}
	if err = tx.Commit(); err != nil {
		return contract.Resource{}, err
	}
	return s.Get(ctx, id)
}

func (s *Store) NextDNSCleanup(ctx context.Context) (time.Time, error) {
	var due sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MIN(json_extract(record_json,'$.notBefore')) FROM certificate_dns_cleanup`).Scan(&due)
	if err != nil || !due.Valid {
		return time.Time{}, err
	}
	return time.UnixMilli(due.Int64), nil
}
