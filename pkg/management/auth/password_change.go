package auth

import (
	"context"
	"time"
)

// StartPasswordChange keeps the current password usable until enrollment commits
// its replacement. Abandoning this short-lived capability cannot remove the last
// administrator's local recovery path. Completing it revokes prior credentials.
func (s *Store) StartPasswordChange(ctx context.Context, actor Principal) (IssuedCredential, error) {
	if actor.CredentialType != "session" || !actor.Allows(IdentityRead) {
		return IssuedCredential{}, ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IssuedCredential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	actor, err = freshRoleActor(ctx, tx, actor)
	if err != nil || !actor.Allows(IdentityRead) {
		return IssuedCredential{}, ErrForbidden
	}
	if _, err := tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE user_id=? AND kind='enrollment'`, actor.UserID); err != nil {
		return IssuedCredential{}, err
	}
	issued, err := issueCredential(ctx, tx, actor.UserID, "enrollment", nil, time.Now().Add(15*time.Minute).Unix())
	if err != nil {
		return IssuedCredential{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE management_credentials SET enrollment_salt=? WHERE id=?`, clientSalt(), issued.ID); err != nil {
		return IssuedCredential{}, err
	}
	if err := recordEvent(ctx, tx, "user.password_change_started", actor.UserID, actor.UserID); err != nil {
		return IssuedCredential{}, err
	}
	return issued, tx.Commit()
}
