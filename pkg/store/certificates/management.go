package certificates

import (
	"context"
)

// BindManagement records the CLI-owned listener's actual reference. The host
// startup inputs remain authoritative; this is only a private deletion guard.
func (s *Store) BindManagement(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var ids []string
	if id != "" {
		ids = []string{id}
	}
	if err := ReplaceReferences(ctx, tx, "management", "cli", "Management HTTPS", ids); err != nil {
		return err
	}
	return tx.Commit()
}
