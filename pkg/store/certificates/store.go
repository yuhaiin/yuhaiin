// Package certificates persists the certificate manager's resources in the
// existing configuration SQLite owner. It never owns a second database handle.
package certificates

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
)

var (
	ErrConflict = errors.New("certificate revision or issuance lease changed")
	ErrInUse    = errors.New("certificate resource is referenced")
)

const MaxResources = 64

type Store struct{ db *sql.DB }

func New(db *sql.DB) *Store { return &Store{db} }

func (s *Store) Get(ctx context.Context, id string) (contract.Resource, error) {
	var r contract.Resource
	var config, status []byte
	err := s.db.QueryRowContext(ctx, `SELECT revision,config_json,status_json FROM managed_certificates WHERE id=?`, id).Scan(&r.Revision, &config, &status)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(config, &r.Config); err != nil {
		return r, err
	}
	if err = json.Unmarshal(status, &r.Status); err != nil {
		return r, err
	}
	r.References, err = s.References(ctx, id)
	return r, err
}

func (s *Store) List(ctx context.Context) ([]contract.Resource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM managed_certificates ORDER BY id LIMIT ?`, MaxResources+1)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err = errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	if len(ids) > MaxResources {
		return nil, errors.New("managed certificate resource limit exceeded")
	}
	result := make([]contract.Resource, 0, len(ids))
	for _, id := range ids {
		r, err := s.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// Save invalidates any in-flight issuance lease. Completion of an old request
// cannot publish material over a newer revision or configuration.
func (s *Store) Save(ctx context.Context, c contract.Config, revision uint64) (contract.Resource, error) {
	if err := c.Validate(); err != nil {
		return contract.Resource{}, err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return contract.Resource{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contract.Resource{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if c.Challenge.Type == "dns-01" {
		var provider []byte
		if err = tx.QueryRowContext(ctx, `SELECT config_json FROM certificate_dns_providers WHERE id=?`, c.Challenge.DNSProviderID).Scan(&provider); err != nil {
			return contract.Resource{}, errors.New("DNS provider is unavailable")
		}
		var p contract.DNSProvider
		if err = json.Unmarshal(provider, &p); err != nil {
			return contract.Resource{}, err
		}
		for _, domain := range c.Domains {
			domain = strings.TrimPrefix(domain, "*.")
			if domain != p.ZoneName && !strings.HasSuffix(domain, "."+p.ZoneName) {
				return contract.Resource{}, errors.New("certificate DNS name is outside provider zone")
			}
		}
	}
	if revision == 0 {
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM managed_certificates`).Scan(&count); err != nil {
			return contract.Resource{}, err
		}
		if count >= MaxResources {
			return contract.Resource{}, errors.New("managed certificate resource limit reached")
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO managed_certificates(id,revision,config_json,status_json) VALUES(?,1,?,?) ON CONFLICT(id) DO NOTHING`, c.ID, string(data), `{"state":"queued"}`)
		if err = changed(result, err); err != nil {
			return contract.Resource{}, err
		}
	} else {
		var previous, statusData []byte
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT config_json,status_json FROM managed_certificates WHERE id=? AND revision=?`, c.ID, revision).Scan(&previous, &statusData); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				err = ErrConflict
			}
			return contract.Resource{}, err
		}
		var old contract.Config
		if err = json.Unmarshal(previous, &old); err != nil {
			return contract.Resource{}, err
		}
		if !slices.Equal(old.Domains, c.Domains) {
			if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM certificate_references WHERE certificate_id=?`, c.ID).Scan(&count); err != nil {
				return contract.Resource{}, err
			}
			if count != 0 {
				return contract.Resource{}, ErrInUse
			}
		}
		var status contract.Status
		if err = json.Unmarshal(statusData, &status); err != nil {
			return contract.Resource{}, err
		}
		if status.State == "issuing" || !slices.Equal(old.Domains, c.Domains) || old.DirectoryURL != c.DirectoryURL || old.TrustPEM != c.TrustPEM {
			status.State = "queued"
			due := time.Now()
			if minimum := status.LastAttempt.Add(ManualAttemptInterval); minimum.After(due) {
				due = minimum
			}
			if status.Failures > 0 && status.NextAttempt.After(due) {
				due = status.NextAttempt
			}
			status.NextAttempt = due
			statusData, err = json.Marshal(status)
			if err != nil {
				return contract.Resource{}, err
			}
		}
		result, err := tx.ExecContext(ctx, `UPDATE managed_certificates SET revision=revision+1,config_json=?,status_json=?,lease_owner='',lease_until=0 WHERE id=? AND revision=?`, string(data), string(statusData), c.ID, revision)
		if err = changed(result, err); err != nil {
			return contract.Resource{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return contract.Resource{}, err
	}
	return s.Get(ctx, c.ID)
}

func changed(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) References(ctx context.Context, id string) ([]contract.Reference, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kind,owner_id,owner_name FROM certificate_references WHERE certificate_id=? ORDER BY kind,owner_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := make([]contract.Reference, 0)
	for rows.Next() {
		var r contract.Reference
		if err := rows.Scan(&r.Kind, &r.ID, &r.Name); err != nil {
			return nil, err
		}
		refs = append(refs, r)
	}
	return refs, rows.Err()
}

// ReplaceReferences runs in the listener configuration's own transaction.
// The foreign key provides deletion protection across concurrent managers.
func ReplaceReferences(ctx context.Context, tx *sql.Tx, kind, id, name string, certificates []string) error {
	if (kind != "gateway" && kind != "management") || id == "" || len(certificates) > 32 {
		return errors.New("invalid certificate reference owner")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM certificate_references WHERE kind=? AND owner_id=?`, kind, id); err != nil {
		return err
	}
	for _, certificate := range certificates {
		if _, err := tx.ExecContext(ctx, `INSERT INTO certificate_references(kind,owner_id,owner_name,certificate_id) VALUES(?,?,?,?)`, kind, id, name, certificate); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, id string, revision uint64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM certificate_references WHERE certificate_id=?`, id).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return ErrInUse
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM managed_certificates WHERE id=? AND revision=?`, id, revision)
	if err = changed(result, err); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Material(ctx context.Context, id string) (Material, error) {
	var m Material
	var key []byte
	err := s.db.QueryRowContext(ctx, `SELECT certificate_pem,private_key_pem FROM managed_certificate_material WHERE certificate_id=?`, id).Scan(&m.CertificatePEM, &key)
	m.PrivateKey = NewSecret(key)
	return m, err
}

// Acquire is durable cross-process deduplication. The caller's operation timeout
// must be shorter than the lease; expired jobs may be recovered after a restart.
func (s *Store) Acquire(ctx context.Context, id string, revision uint64, owner string, now time.Time, ttl time.Duration) (bool, error) {
	if !contract.ValidID(owner) || ttl <= 0 || ttl > 15*time.Minute {
		return false, errors.New("invalid certificate issuance lease")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE managed_certificates SET lease_owner=?,lease_until=?,status_json=json_set(status_json,'$.state','issuing','$.lastAttempt',?,'$.nextAttempt',?) WHERE id=? AND revision=? AND lease_until<=?`, owner, now.Add(ttl).UnixMilli(), now.UTC().Format(time.RFC3339Nano), now.Add(ttl).UTC().Format(time.RFC3339Nano), id, revision, now.UnixMilli())
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// Complete atomically publishes a validated pair and status, or just failure
// status while retaining the old pair. A stale job cannot clear another lease.
func (s *Store) Complete(ctx context.Context, id string, revision uint64, owner string, now time.Time, status contract.Status, material *Material) error {
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if material != nil && (len(material.CertificatePEM) == 0 || len(material.CertificatePEM) > 256<<10 || material.PrivateKey.Empty() || len(material.PrivateKey.value) > 32<<10) {
		return errors.New("invalid certificate material bounds")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE managed_certificates SET status_json=?,lease_owner='',lease_until=0 WHERE id=? AND revision=? AND lease_owner=? AND lease_until>?`, string(data), id, revision, owner, now.UnixMilli())
	if err = changed(result, err); err != nil {
		return err
	}
	if material != nil {
		if _, err = tx.ExecContext(ctx, `INSERT INTO managed_certificate_material(certificate_id,certificate_pem,private_key_pem) VALUES(?,?,?) ON CONFLICT(certificate_id) DO UPDATE SET certificate_pem=excluded.certificate_pem,private_key_pem=excluded.private_key_pem`, id, material.CertificatePEM, material.PrivateKey.value); err != nil {
			return err
		}
	}
	return tx.Commit()
}
