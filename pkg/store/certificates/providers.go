package certificates

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
)

func ValidProvider(p contract.DNSProvider) bool {
	zone, err := hex.DecodeString(p.ZoneID)
	return contract.ValidID(p.ID) && p.Name != "" && len(p.Name) <= 128 && p.Type == "cloudflare" && err == nil && len(zone) == 16 && strings.ToLower(p.ZoneID) == p.ZoneID && contract.ValidDomain(p.ZoneName, false)
}

func (s *Store) Provider(ctx context.Context, id string) (contract.DNSProvider, Secret, error) {
	var p contract.DNSProvider
	var data, key []byte
	err := s.db.QueryRowContext(ctx, `SELECT revision,config_json,token FROM certificate_dns_providers WHERE id=?`, id).Scan(&p.Revision, &data, &key)
	if err != nil {
		return p, Secret{}, err
	}
	if err = json.Unmarshal(data, &p); err != nil {
		return p, Secret{}, err
	}
	p.HasCredential = len(key) > 0
	return p, NewSecret(key), nil
}

func (s *Store) Providers(ctx context.Context) ([]contract.DNSProvider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM certificate_dns_providers ORDER BY id LIMIT ?`, MaxResources+1)
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
		return nil, errors.New("DNS provider limit exceeded")
	}
	result := make([]contract.DNSProvider, 0, len(ids))
	for _, id := range ids {
		p, _, err := s.Provider(ctx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, nil
}

// SaveProvider accepts a write-only token. An empty token on update preserves
// the existing credential; clearing it requires deleting an unused provider.
func (s *Store) SaveProvider(ctx context.Context, p contract.DNSProvider, token Secret) (contract.DNSProvider, error) {
	if !ValidProvider(p) {
		return p, errors.New("invalid Cloudflare DNS provider or zone")
	}
	if !token.Empty() {
		if len(token.value) > 4096 {
			return p, errors.New("DNS provider token exceeds limit")
		}
		for _, c := range token.value {
			if c < 33 || c > 126 {
				return p, errors.New("DNS provider token must be a nonempty ASCII bearer token")
			}
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer func() { _ = tx.Rollback() }()
	if p.Revision == 0 {
		if token.Empty() {
			return p, errors.New("DNS provider token is required")
		}
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM certificate_dns_providers`).Scan(&count); err != nil {
			return p, err
		}
		if count >= MaxResources {
			return p, errors.New("DNS provider limit reached")
		}
		p.Revision = 1
		p.HasCredential = !token.Empty()
		data, err := json.Marshal(p)
		if err != nil {
			return p, err
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO certificate_dns_providers(id,revision,config_json,token) VALUES(?,1,?,?) ON CONFLICT(id) DO NOTHING`, p.ID, string(data), token.value)
		if err = changed(result, err); err != nil {
			return p, err
		}
	} else {
		var data, key []byte
		var old contract.DNSProvider
		err = tx.QueryRowContext(ctx, `SELECT config_json,token FROM certificate_dns_providers WHERE id=? AND revision=?`, p.ID, p.Revision).Scan(&data, &key)
		if errors.Is(err, sql.ErrNoRows) {
			return p, ErrConflict
		}
		if err != nil {
			return p, err
		}
		if err = json.Unmarshal(data, &old); err != nil {
			return p, err
		}
		if p.ZoneID != old.ZoneID || p.ZoneName != old.ZoneName || p.Type != old.Type {
			if err = providerUnused(ctx, tx, p.ID); err != nil {
				return p, err
			}
		}
		if token.Empty() {
			token = NewSecret(key)
		}
		oldRevision := p.Revision
		p.Revision++
		p.HasCredential = !token.Empty()
		data, err = json.Marshal(p)
		if err != nil {
			return p, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE certificate_dns_providers SET revision=?,config_json=?,token=? WHERE id=? AND revision=?`, p.Revision, string(data), token.value, p.ID, oldRevision)
		if err = changed(result, err); err != nil {
			return p, err
		}
	}
	return p, tx.Commit()
}

func providerUnused(ctx context.Context, tx *sql.Tx, id string) error {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM managed_certificates WHERE json_extract(config_json,'$.challenge.dnsProviderId')=?)+(SELECT COUNT(*) FROM certificate_dns_cleanup WHERE provider_id=?)`, id, id).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return ErrInUse
	}
	return nil
}

func (s *Store) DeleteProvider(ctx context.Context, id string, revision uint64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err = providerUnused(ctx, tx, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM certificate_dns_providers WHERE id=? AND revision=?`, id, revision)
	if err = changed(result, err); err != nil {
		return err
	}
	return tx.Commit()
}
