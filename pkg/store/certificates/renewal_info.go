package certificates

import (
	"context"
	"errors"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
)

// AcquireRenewalInfo shares the existing issuance lease. A metadata refresh does
// not become an issuance attempt, reset backoff or replace any key material.
// Complete publishes the resulting status with the same revision/owner fencing.
func (s *Store) AcquireRenewalInfo(ctx context.Context, id string, revision uint64, serial, owner string, now time.Time) (bool, error) {
	if !contract.ValidID(owner) || serial == "" || len(serial) > 128 {
		return false, errors.New("invalid certificate renewal information lease")
	}
	until := now.Add(2 * time.Minute)
	result, err := s.db.ExecContext(ctx, `UPDATE managed_certificates SET lease_owner=?,lease_until=?,status_json=json_set(status_json,'$.renewalInfo.nextCheck',?) WHERE id=? AND revision=? AND lease_until<=? AND json_extract(status_json,'$.state')='ready' AND json_extract(status_json,'$.serial')=? AND json_extract(config_json,'$.autoRenew')=1`, owner, until.UnixMilli(), until.UTC().Format(time.RFC3339Nano), id, revision, now.UnixMilli(), serial)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}
