package certificates

import "context"

// PrepareClone runs only against isolated, authenticated restore staging. A new
// instance must not renew the source's certificates, reuse its account/site keys,
// or delete its pending DNS records. Public resources and disabled Gateway
// references remain available for an administrator to re-enroll explicitly.
func (s *Store) PrepareClone(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range []string{
		`DELETE FROM certificate_dns_cleanup`,
		`DELETE FROM certificate_acme_accounts`,
		`DELETE FROM managed_certificate_material`,
		`DELETE FROM certificate_references WHERE kind='management'`,
		`UPDATE certificate_dns_providers SET revision=revision+1,token=x'',config_json=json_set(config_json,'$.hasCredential',json('false'),'$.revision',revision+1)`,
		`UPDATE managed_certificates SET revision=revision+1,config_json=json_set(config_json,'$.autoRenew',json('false')),status_json='{"state":"disabled"}',lease_owner='',lease_until=0`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}
