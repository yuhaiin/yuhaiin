package certificates

import (
	"context"
	"encoding/json/v2"
	"errors"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
)

const MaxDNSCleanup = 256

// DNSCleanup records ownership before the provider request. NotBefore also
// fences reconciliation of an ambiguous create until the request has expired.
// There are no provider credentials in the receipt.
type DNSCleanup struct {
	ID         string `json:"id"`
	ProviderID string `json:"providerId"`
	Name       string `json:"name"`
	Value      string `json:"value"`
	RecordID   string `json:"recordId,omitempty"`
	NotBefore  int64  `json:"notBefore"`
}

func (s *Store) AddDNSCleanup(ctx context.Context, r DNSCleanup, now time.Time) error {
	if !contract.ValidID(r.ID) || !contract.ValidID(r.ProviderID) || len(r.Name) > 270 || len(r.Value) > 128 || r.NotBefore < now.UnixMilli() {
		return errors.New("invalid DNS cleanup receipt")
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM certificate_dns_cleanup`).Scan(&count); err != nil {
		return err
	}
	if count >= MaxDNSCleanup {
		return errors.New("pending DNS cleanup limit reached")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO certificate_dns_cleanup(id,provider_id,record_json,created_at) VALUES(?,?,?,?)`, r.ID, r.ProviderID, string(data), now.UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateDNSCleanup(ctx context.Context, r DNSCleanup) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE certificate_dns_cleanup SET record_json=? WHERE id=? AND provider_id=?`, string(data), r.ID, r.ProviderID)
	return changed(result, err)
}

func (s *Store) PendingDNSCleanup(ctx context.Context, now time.Time) ([]DNSCleanup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT record_json FROM certificate_dns_cleanup WHERE json_extract(record_json,'$.notBefore')<=? ORDER BY created_at,id LIMIT ?`, now.UnixMilli(), MaxDNSCleanup)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]DNSCleanup, 0)
	for rows.Next() {
		var data []byte
		var r DNSCleanup
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *Store) FinishDNSCleanup(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM certificate_dns_cleanup WHERE id=?`, id)
	return err
}
